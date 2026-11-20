#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <setupapi.h>

#include <string>
#include <vector>

#include "SchedTask.h"

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Setupapi.lib")

static const wchar_t *AURemovalTaskName = L"NpcapRemoveAuFromACL";

// Use the same class GUID passed to IoCreateDeviceSecure in Packet.c.
static const GUID guidClassNPF = {
    0x26e0d1e0L, 0x8189, 0x12e0,
    { 0x99, 0x14, 0x08, 0x00, 0x22, 0x30, 0x19, 0x04 }
};

using SidBuffer = BYTE[SECURITY_MAX_SID_SIZE];
using SidBufferTable = SidBuffer[3];

BOOL GetNpcapUsersSID(const wchar_t *groupName, SidBuffer &sidBuffer, DWORD *errorOut)
{
	wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD computerNameLength = ARRAYSIZE(computerName);
    DWORD error = ERROR_SUCCESS;

    if (errorOut)
        *errorOut = ERROR_SUCCESS;

	do {
		if (!GetComputerNameW(computerName, &computerNameLength)) {
			error = GetLastError();
			break;
		}

		std::wstring accountName(computerName);
		accountName += L"\\";
		accountName += groupName;

		SID_NAME_USE sidType;
        DWORD SidSize = sizeof(sidBuffer);
        DWORD cchDomain = 0;
		if (!LookupAccountNameW(
					nullptr,
					accountName.c_str(),
					reinterpret_cast<PSID>(sidBuffer),
					&SidSize,
                    nullptr,
					&cchDomain,
					&sidType)) {
			error = GetLastError();
			break;
		}

		// Confirm that the resolved account is a group.
		if (sidType != SidTypeAlias && sidType != SidTypeGroup) {
			error = ERROR_INVALID_SID;
			break;
		}
		return TRUE;
	} while (FALSE);

    if (errorOut)
        *errorOut = error;
    return FALSE;
}


static SidBufferTable& getSidBuffers()
{
    static BYTE sidBuffers[3][SECURITY_MAX_SID_SIZE];
    static BOOL sidBuffersInitialized = FALSE;
    if (sidBuffersInitialized) {
        return sidBuffers;
    }

    static const WELL_KNOWN_SID_TYPE sidTypes[] = {
        WinLocalSystemSid,
        WinBuiltinAdministratorsSid,
        WinAuthenticatedUserSid
    };
    for (DWORD i = 0; i < 3; i++) {
        DWORD sidSize = sizeof(sidBuffers[i]);

        if (!CreateWellKnownSid(
                sidTypes[i],
                NULL,
                sidBuffers[i],
                &sidSize)) {
            return sidBuffers;
        }
    }
    sidBuffersInitialized = TRUE;
    return sidBuffers;
}


static NET_API_STATUS AddWellKnownMembers(
    const wchar_t *groupName,
    BOOL bAdminOnly)
{
    const SidBufferTable &sidBuffers = getSidBuffers();
    LOCALGROUP_MEMBERS_INFO_0 members[3] = {};

    DWORD count = bAdminOnly ? 2 : 3;
    for (DWORD i = 0; i < count; i++) {
        members[i].lgrmi0_sid = (PSID)sidBuffers[i];
    }

    return NetLocalGroupAddMembers(
        NULL,
        const_cast<LPCWSTR>(groupName),
        0,                  // LOCALGROUP_MEMBERS_INFO_0
        (LPBYTE)members,
        count
    );
}

static BOOL CheckExpectedGroupMembers(
    const wchar_t *groupName,
    BOOL bAdminOnly)
{
    const SidBufferTable &sidBuffers = getSidBuffers();
    DWORD count = bAdminOnly ? 2 : 3;

    LOCALGROUP_MEMBERS_INFO_0 *members = nullptr;
    DWORD entriesread = 0;
    DWORD totalentries = 0;

    NET_API_STATUS status = NetLocalGroupGetMembers(
        nullptr,
        const_cast<LPCWSTR>(groupName),
        0,                  // LOCALGROUP_MEMBERS_INFO_0
        (LPBYTE *) &members,
        count * sizeof(LOCALGROUP_MEMBERS_INFO_0),
        &entriesread,
        &totalentries,
        nullptr
    );

    if (status != NERR_Success) {
        return FALSE;
    }
    return TRUE;
}

BOOL ScheduleAURemovalTask() {
    wchar_t buffer[MAX_PATH] = L"";
    GetModuleFileNameW(NULL, buffer, MAX_PATH);

    return CreateBootTask(AURemovalTaskName, buffer, L"-ua");
}

BOOL DeleteAURemovalTask() {
    return DeleteScheduledTask(AURemovalTaskName);
}

// Configures the Npcap device-class security descriptor to grant
// access to SYSTEM, Administrators, and members of the local
// "Npcap Users" group.
//
// Returns TRUE on success. On failure, *errorOut receives an error
// code from NetAPI or GetLastError, depending on the failing operation.
//
// The caller must run with sufficient administrative privileges.
BOOL ConfigureNpcapUsersSecurity(DWORD *errorOut, BOOL bAdminOnly)
{
    BOOL bGroupCreated = FALSE;
    BOOL bAddAUtoSDDL = FALSE;
    const wchar_t *groupName = L"Npcap Users";
    const wchar_t *groupComment =
        L"Users permitted to access Npcap packet capture devices";

    DWORD error = ERROR_SUCCESS;

    if (errorOut)
        *errorOut = ERROR_SUCCESS;

    do {
        // 1. Create the local group if it does not exist.
        LOCALGROUP_INFO_1 groupInfo = {};
        groupInfo.lgrpi1_name = const_cast<LPWSTR>(groupName);
        groupInfo.lgrpi1_comment = const_cast<LPWSTR>(groupComment);

        NET_API_STATUS status = NetLocalGroupAdd(
                nullptr,  // Local computer
                1,        // LOCALGROUP_INFO_1
                reinterpret_cast<LPBYTE>(&groupInfo),
                nullptr   // No parameter-error output needed
                );

        bGroupCreated = (status != NERR_GroupExists);
        if (status != NERR_Success && status != NERR_GroupExists) {
            error = static_cast<DWORD>(status);
            break;
        }

        if (bGroupCreated) {
            bAddAUtoSDDL = TRUE;
            status = AddWellKnownMembers(groupName, bAdminOnly);
            if (status != NERR_Success) {
                error = static_cast<DWORD>(status);
                break;
            }
        }

        // 2. Resolve the local group's SID.
        SidBuffer sidBuffer = {0};
        if (!GetNpcapUsersSID(groupName, sidBuffer, &error)) {
            break;
        }

        // 3. Convert the binary SID to the string form accepted by SDDL.
        LPWSTR sidString = nullptr;

        if (!ConvertSidToStringSidW(
                    reinterpret_cast<PSID>(sidBuffer),
                    &sidString)) {
            error = GetLastError();
            break;
        }

        std::wstring sddl =
            L"D:P"
            L"(A;;GA;;;SY)"  // SYSTEM: generic all
            L"(A;;GA;;;BA)"  // Built-in Administrators: generic all
            L"(A;;GRGW;;;";

        sddl += sidString;
        sddl += L")";

        LocalFree(sidString);

        if (bGroupCreated && !bAdminOnly) {
            // If we created the group, any currently-logged-in users won't
            // have the group in their token. Distribution licensees and system
            // admins ought to understand that and do a login/logout to refresh
            // their token, but in the common case where all users are allowed,
            // we want people to be able to use Npcap immediately, so we add
            // Authenticated Users to the device class ACL and schedule a task
            // to remove it at next boot, since all tokens will be new from
            // then forward.
            // For safety, we only add it if we know we successfully scheduled
            // the removal.
            if (ScheduleAURemovalTask()) {
                sddl += L"(A;;GRGW;;;AU)";
            }
        }


        // 4. Set the device-class security descriptor.
        //
        // SPCRP_SECURITY_SDS expects an SDDL string. The buffer size
        // includes the terminating null character.
        const DWORD sddlSize = static_cast<DWORD>(
                sddl.size() * sizeof(wchar_t) + sizeof(wchar_t));

        if (!SetupDiSetClassRegistryPropertyW(
                    &guidClassNPF,
                    SPCRP_SECURITY_SDS,
                    reinterpret_cast<const BYTE *>(sddl.c_str()),
                    sddlSize,
                    0,
                    nullptr)) {
            error = GetLastError();
            break;
        }

        return TRUE;
    } while (FALSE);

    if (bGroupCreated) {
        NET_API_STATUS status = NetLocalGroupDel(
                nullptr,  // Local computer
                const_cast<LPWSTR>(groupName)
                );
    }
    if (errorOut)
        *errorOut = error;
    return FALSE;
}
