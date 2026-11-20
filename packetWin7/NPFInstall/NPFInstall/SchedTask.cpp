#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>

// Link against the Task Scheduler library
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

static const wchar_t *RootFolderName = L"\\";

struct NpcapTaskScheduler {
    bool bInitialized;
    ITaskService* pService;
    ITaskFolder* pFolder;
    NpcapTaskScheduler()
        : bInitialized(false), pService(nullptr), pFolder(nullptr)
    {}
};

static bool OpenTaskScheduler(NpcapTaskScheduler *nts) {
    // 1. Initialize COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"CoInitializeEx failed: 0x" << std::hex << hr << std::endl;
        return false;
    }

    // 2. Set general COM security levels (required for Task Scheduler)
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL
    );

    // RPC_E_TOO_LATE means security was already initialized in this process, which is fine
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::wcerr << L"CoInitializeSecurity failed: 0x" << std::hex << hr << std::endl;
        CoUninitialize();
        nts->bInitialized = false;
        return false;
    }
    nts->bInitialized = true;

    // 3. Create an instance of the Task Service
    hr = CoCreateInstance(
        CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&nts->pService
    );

    if (SUCCEEDED(hr)) {
        // 4. Connect to the local Task Scheduler service
        hr = nts->pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (SUCCEEDED(hr)) {
            // 5. Get the folder containing the task (default is root "\")
            hr = nts->pService->GetFolder(_bstr_t(RootFolderName), &nts->pFolder);
            if (SUCCEEDED(hr)) {
                return true;
            }
            else {
                std::wcerr << L"Cannot get folder '" << RootFolderName << L"'. Error: 0x" << std::hex << hr << std::endl;
            }
            nts->pService->Release();
            nts->pService = nullptr;
        }
        else {
            std::wcerr << L"ITaskService::Connect failed: 0x" << std::hex << hr << std::endl;
        }
        CoUninitialize();
        nts->bInitialized = false;
    }
    else {
        std::wcerr << L"Failed to create ITaskService instance: 0x" << std::hex << hr << std::endl;
    }
    return false;
}

static void CloseTaskScheduler(NpcapTaskScheduler *nts) {
    if (!nts->bInitialized)
        return;
    if (nts->pFolder)
        nts->pFolder->Release();
    if (nts->pService)
        nts->pService->Release();
    CoUninitialize();
}

bool DeleteScheduledTask(const wchar_t* taskName) {
    NpcapTaskScheduler nts;
    if (!OpenTaskScheduler(&nts)) {
        return false;
    }
    // Delete the task by name (flags parameter must be 0)
    HRESULT hr = nts.pFolder->DeleteTask(_bstr_t(taskName), 0);
                
    bool success = false;
    if (SUCCEEDED(hr)) {
        std::wcout << L"Task '" << taskName << L"' successfully deleted." << std::endl;
        success = true;
    } else {
        std::wcerr << L"Failed to delete task. Error: 0x" << std::hex << hr << std::endl;
    }

    CloseTaskScheduler(&nts);

    return success;
}

bool CreateBootTask(const wchar_t* taskName, const wchar_t* exePath, const wchar_t* arguments) {
    NpcapTaskScheduler nts;
    if (!OpenTaskScheduler(&nts)) {
        return false;
    }

    // 1. Create a task definition object
    ITaskDefinition* pTask = NULL;
    HRESULT hr = nts.pService->NewTask(0, &pTask); // Note: pService needs to be accessible in your scope
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create task definition: 0x" << std::hex << hr << std::endl;
        CloseTaskScheduler(&nts);
        return false;
    }

    // 2. Set general task information (optional: author, description)
    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (SUCCEEDED(hr)) {
        pRegInfo->put_Author(L"System Boot Task Manager");
        pRegInfo->Release();
    }

    // 3. Configure Principal (Run with highest privileges / Administrator context, usually required for boot tasks)
    IPrincipal* pPrincipal = NULL;
    hr = pTask->get_Principal(&pPrincipal);
    if (SUCCEEDED(hr)) {
        // Run as Built-in Administrators group or LOCAL_SYSTEM
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT); // Or TASK_LOGON_INTERACTIVE_TOKEN
        pPrincipal->Release();
    }

    // 4. Set Settings (e.g., allow demand start, don't stop on battery)
    ITaskSettings* pSettings = NULL;
    hr = pTask->get_Settings(&pSettings);
    if (SUCCEEDED(hr)) {
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->Release();
    }

    // 5. Add a Boot Trigger
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (SUCCEEDED(hr)) {
        ITrigger* pTrigger = NULL;
        hr = pTriggerCollection->Create(TASK_TRIGGER_BOOT, &pTrigger);
        if (SUCCEEDED(hr)) {
            IBootTrigger* pBootTrigger = NULL;
            hr = pTrigger->QueryInterface(IID_IBootTrigger, (void**)&pBootTrigger);
            if (SUCCEEDED(hr)) {
                // Optional delay after boot (e.g., delay 30 seconds to let services stabilize)
                pBootTrigger->put_Delay(L"PT30S"); 
                pBootTrigger->Release();
            }
            pTrigger->Release();
        }
        pTriggerCollection->Release();
    }

    // 6. Add the Action (Executable path + command line arguments)
    IActionCollection* pActionCollection = NULL;
    hr = pTask->get_Actions(&pActionCollection);
    if (SUCCEEDED(hr)) {
        IAction* pAction = NULL;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            IExecAction* pExecAction = NULL;
            hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            if (SUCCEEDED(hr)) {
                pExecAction->put_Path(_bstr_t(exePath));
                pExecAction->put_Arguments(_bstr_t(arguments));
                pExecAction->Release();
            }
            pAction->Release();
        }
        pActionCollection->Release();
    }

    // 7. Register (save) the task into the folder
    IRegisteredTask* pRegisteredTask = NULL;
    hr = nts.pFolder->RegisterTaskDefinition(
        _bstr_t(taskName), 
        pTask, 
        TASK_CREATE_OR_UPDATE, 
        _variant_t(), // User ID (empty for current context/SYSTEM)
        _variant_t(), // Password
        TASK_LOGON_SERVICE_ACCOUNT, 
        _variant_t(L""), 
        &pRegisteredTask
    );

    pTask->Release();
    bool success = SUCCEEDED(hr);
    if (success) {
        if (pRegisteredTask) pRegisteredTask->Release();
        std::wcout << L"Successfully created boot task: " << taskName << std::endl;
    } else {
        std::wcerr << L"Failed to register task. Error: 0x" << std::hex << hr << std::endl;
    }
    CloseTaskScheduler(&nts);
    return success;
}
