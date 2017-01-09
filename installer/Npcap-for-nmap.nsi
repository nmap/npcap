;; Npcap - Nmap Project's packet sniffing library for Windows, based on WinPcap/Libpcap improved with NDIS 6 and LWF
;; http://www.npcap.org
;; Recognizes the options (case sensitive):
;; /S				silent install
;; /NPFSTARTUP=NO	start NPF now and at startup (only has effect with /S)

;; Started by Doug Hoyte, April 2006

;; Eddie Bell
;; Updated to 4.0, June 2007
;; Updated to 4.01, July 2007
;; Updated to 4.02, November 2007

;; Rob Nicholls
;; Updated to 4.1.1, October 2009
;; Updated to 4.1.2, July 2010

;; Yang Luo
;; Updated to 4.1.3, August 2013

;--------------------------------
;Include Modern UI

!include "MUI.nsh"
!include "FileFunc.nsh"
; !include "EnvVarUpdate.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

;--------------------------------
;General

; Get the version strings from the C header
!include "..\version.h"

; The version of Npcap
!define VERSION "${WINPCAP_VER_STRING}"
!searchreplace INSTALLER_VERSION "${VERSION}" " r" "-r"
!define WIN_VERSION "${WINPCAP_MAJOR}.${WINPCAP_MINOR}.${WINPCAP_REV}.${WINPCAP_BUILD}"

; The system restore point name created by Npcap installer
!define RESTORE_POINT_NAME_INSTALL "Before installation of Npcap ${VERSION}"
!define RESTORE_POINT_NAME_UNINSTALL "Before uninstallation of Npcap ${VERSION}"

; The name of the installer
Name "Npcap ${VERSION}"

;--------------------------------
; Sign the uninstaller
; http://nsis.sourceforge.net/Signing_an_Uninstaller

!ifdef INNER
  !echo "Inner invocation"                  ; just to see what's going on
  OutFile "$%TEMP%\tempinstaller.exe"       ; not really important where this is
  SetCompress off                           ; for speed
!else
  !echo "Outer invocation"

  !ifndef SIGNCMD
    !echo "Need to define SIGNCMD"
    quit
  !endif
  !warning "SIGNCMD=>${SIGNCMD}<"
  ; Call makensis again, defining INNER.  This writes an installer for us which, when
  ; it is invoked, will just write the uninstaller to some location, and then exit.
  ; Be sure to substitute the name of this script here.

  !system "$\"${NSISDIR}\makensis$\" /DINNER Npcap-for-nmap.nsi" = 0

  ; So now run that installer we just created as %TEMP%\tempinstaller.exe.  Since it
  ; calls quit the return value isn't zero.

  !system "$\"$%TEMP%\tempinstaller.exe$\"" = 2

  ; That will have written an uninstaller binary for us.  Now we sign it with your
  ; favourite code signing tool.

  ;!system "icacls.exe $\"$%TEMP%\Uninstall.exe$\" /grant $\"$%USER%$\":M"
  !system "copy /b $\"$%TEMP%\Uninstall.exe$\" Uninstall.exe"
  !system "$\"${SIGNCMD}$\" ${SIGNARGS} Uninstall.exe" = 0

  ; Good.  Now we can carry on writing the real installer.

; The file to write
; OutFile "npcap-${INSTALLER_VERSION}.exe"
  SetCompressor /SOLID /FINAL lzma
!endif


Var /GLOBAL inst_ver
Var /GLOBAL my_ver
Var /GLOBAL UNINSTDIR
Var /GLOBAL INSTDIR_DEFAULT

Var /GLOBAL is_64bit
Var /GLOBAL os_ver
Var /GLOBAL ndis6_driver
Var /GLOBAL attestation_signed
Var /GLOBAL cmd_line
Var /GLOBAL service_name

; Installer options:
Var /GLOBAL npf_startup
Var /GLOBAL loopback_support
Var /GLOBAL dlt_null
Var /GLOBAL admin_only
Var /GLOBAL dot11_support
Var /GLOBAL vlan_support
Var /GLOBAL winpcap_mode
Var /GLOBAL sign_mode

; Uninstaller options:
Var /GLOBAL no_confirm
Var /GLOBAL no_kill

; For internal use:
Var /GLOBAL err_flag
Var /GLOBAL cur_system_folder
Var /GLOBAL install_ok

Var /GLOBAL restore_point_success
Var /GLOBAL has_wlan_card
Var /GLOBAL winpcap_installed

!ifndef INNER
; Avoid elevation dialog during build process
RequestExecutionLevel admin
!endif

; These leave either "1" or "0" in $0.
!macro MACRO_is64bit un
Function ${un}is64bit
	System::Call "kernel32::GetCurrentProcess() i .s"
	System::Call "kernel32::IsWow64Process(i s, *i .r0)"
FunctionEnd
!macroend
!insertmacro MACRO_is64bit ""
; !insertmacro MACRO_is64bit "un."

!define StrRep "!insertmacro StrRep"
!macro StrRep output string old new
    Push `${string}`
    Push `${old}`
    Push `${new}`
    !ifdef __UNINSTALL__
        Call un.StrRep
    !else
        Call StrRep
    !endif
    Pop ${output}
!macroend
 
!macro Func_StrRep un
    Function ${un}StrRep
        Exch $R2 ;new
        Exch 1
        Exch $R1 ;old
        Exch 2
        Exch $R0 ;string
        Push $R3
        Push $R4
        Push $R5
        Push $R6
        Push $R7
        Push $R8
        Push $R9
 
        StrCpy $R3 0
        StrLen $R4 $R1
        StrLen $R6 $R0
        StrLen $R9 $R2
        loop:
            StrCpy $R5 $R0 $R4 $R3
            StrCmp $R5 $R1 found
            StrCmp $R3 $R6 done
            IntOp $R3 $R3 + 1 ;move offset by 1 to check the next character
            Goto loop
        found:
            StrCpy $R5 $R0 $R3
            IntOp $R8 $R3 + $R4
            StrCpy $R7 $R0 "" $R8
            StrCpy $R0 $R5$R2$R7
            StrLen $R6 $R0
            IntOp $R3 $R3 + $R9 ;move offset by length of the replacement string
            Goto loop
        done:
 
        Pop $R9
        Pop $R8
        Pop $R7
        Pop $R6
        Pop $R5
        Pop $R4
        Pop $R3
        Push $R0
        Push $R1
        Pop $R0
        Pop $R1
        Pop $R0
        Pop $R2
        Exch $R1
    FunctionEnd
!macroend
; !insertmacro Func_StrRep ""
!insertmacro Func_StrRep "un."

VIProductVersion "${WIN_VERSION}"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "Npcap"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "FileDescription" "Npcap ${VERSION} installer"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright 2016 Insecure.Com LLC ($\"The Nmap Project$\")"

;--------------------------------
; Windows API Definitions

!define SC_MANAGER_ALL_ACCESS					0x3F
!define SERVICE_ALL_ACCESS						0xF01FF

; Service Types
!define SERVICE_FILE_SYSTEM_DRIVER				0x00000002
!define SERVICE_KERNEL_DRIVER					0x00000001
!define SERVICE_WIN32_OWN_PROCESS				0x00000010
!define SERVICE_WIN32_SHARE_PROCESS				0x00000020
!define SERVICE_INTERACTIVE_PROCESS				0x00000100

; Service start options
!define SERVICE_AUTO_START						0x00000002
!define SERVICE_BOOT_START						0x00000000
!define SERVICE_DEMAND_START					0x00000003
!define SERVICE_DISABLED						0x00000004
!define SERVICE_SYSTEM_START					0x00000001

; Service Error control
!define SERVICE_ERROR_CRITICAL					0x00000003
!define SERVICE_ERROR_IGNORE					0x00000000
!define SERVICE_ERROR_NORMAL					0x00000001
!define SERVICE_ERROR_SEVERE					0x00000002

; Service Control Options
!define SERVICE_CONTROL_STOP					0x00000001
!define SERVICE_CONTROL_PAUSE					0x00000002



;--------------------------------
;Interface Settings

!define MUI_ABORTWARNING

;--------------------------------
;Logo

!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "nmap-logo.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "nmap-logo.bmp"

;--------------------------------
;Pages

!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
Page custom OptionsPage doOptions
; Don't let user choose where to install the files. WinPcap doesn't let people, and it's one less thing for us to worry about.
!insertmacro MUI_PAGE_INSTFILES
!define MUI_PAGE_CUSTOMFUNCTION_PRE un.doPreConfirm
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
Page custom finalPage doFinal

;--------------------------------
;Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Reserves

ReserveFile "options.ini"
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------

!insertmacro GetParameters
!insertmacro GetOptions

Function un.doPreConfirm
	${If} $no_confirm == "yes"
		Abort
	${EndIf}
Functionend

Function getInstallOptions
	StrCpy $npf_startup "yes"
	StrCpy $loopback_support "yes"
	StrCpy $dlt_null "enforced"
	StrCpy $admin_only "no"
	StrCpy $dot11_support "no"
	StrCpy $vlan_support "no"
	StrCpy $winpcap_mode "no"
	StrCpy $sign_mode ""
	StrCpy $winpcap_installed "no"

	${If} ${FileExists} "C:\npcap_install_options.txt"
		FileOpen $4 "C:\npcap_install_options.txt" r
		FileRead $4 $cmd_line ; we read until the end of line (including carriage return and new line) and save it to $1
		FileClose $4 ; and close the file
	${Else}
		${GetParameters} $cmd_line ; An example: $cmd_line = '/npf_startup=yes /loopback_support=yes /dlt_null=no /admin_only=no /dot11_support=no /vlan_support=no /winpcap_mode=no /sign_mode=sha2'
	${EndIf}

	${GetOptions} $cmd_line "/npf_startup=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $npf_startup $R0
	${EndIf}

	${GetOptions} $cmd_line "/loopback_support=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $loopback_support $R0
	${EndIf}

	${GetOptions} $cmd_line "/dlt_null=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $dlt_null $R0
	${EndIf}

	${GetOptions} $cmd_line "/admin_only=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $admin_only $R0
	${EndIf}

	${GetOptions} $cmd_line "/dot11_support=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $dot11_support $R0
	${EndIf}

	${GetOptions} $cmd_line "/vlan_support=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $vlan_support $R0
	${EndIf}

	${GetOptions} $cmd_line "/winpcap_mode=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "yes2"
	${OrIf} $R0 S== "no"
	${OrIf} $R0 S== "disabled"
		StrCpy $winpcap_mode $R0
	${EndIf}

	${GetOptions} $cmd_line "/sign_mode=" $R0
	${If} $R0 S== "sha1"
	${OrIf} $R0 S== "sha2"
		StrCpy $sign_mode $R0
	${EndIf}
FunctionEnd

Function un.getInstallOptions
	StrCpy $no_confirm "no"
	StrCpy $no_kill "no"

	${GetParameters} $cmd_line ; An example: $cmd_line = '/Q'

	${GetOptions} $cmd_line "/Q" $R0
	${If} ${Errors}
		StrCpy $no_confirm "no"
	${Else}
		StrCpy $no_confirm "yes"
	${EndIf}

	${GetOptions} $cmd_line "/no_kill=" $R0
	${If} $R0 S== "yes"
	${OrIf} $R0 S== "no"
		StrCpy $no_kill $R0
	${EndIf}
FunctionEnd

; This function is called on startup. IfSilent checks
; if the flag /S was specified. If so, it sets the installer
; to run in "silent mode" which displays no windows and accepts
; all defaults.

; We also check if there is a previously installed winpcap
; on this system. If it's the same as the version we're installing,
; abort the install. If not, prompt the user about whether to
; replace it or not.

Function .onInit
  !ifdef INNER
    ; If INNER is defined, then we aren't supposed to do anything except write out
    ; the installer.  This is better than processing a command line option as it means
    ; this entire code path is not present in the final (real) installer.

    WriteUninstaller "$%TEMP%\Uninstall.exe"
    Quit  ; just bail out quickly when running the "inner" installer
  !endif
  
	!insertmacro MUI_INSTALLOPTIONS_EXTRACT "options.ini"
	!insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"

	StrCpy $my_ver "${VERSION}"
	StrCpy $err_flag ""

	; On 64-bit Windows, $PROGRAMFILES is "C:\Program Files (x86)" and
	; $PROGRAMFILES64 is "C:\Program Files". We want "C:\Program Files"
	; on 32-bit or 64-bit.
	Call is64bit
	${If} $0 == "0"
		StrCpy $is_64bit "no"
	${Else}
		StrCpy $is_64bit "yes"
	${EndIf}

	${If} $is_64bit == "no"
		StrCpy $INSTDIR_DEFAULT "$PROGRAMFILES\Npcap"
	${Else}
		StrCpy $INSTDIR_DEFAULT "$PROGRAMFILES64\Npcap"
	${EndIf}

	; If the user doesn't specify the installation path via "/D=", we will use the default path.
	${If} $INSTDIR == ""
		StrCpy $INSTDIR $INSTDIR_DEFAULT
	${EndIf}

	; write the installation log to $INSTDIR\install.log
	LogSet on

    Call checkWindowsVersion
	DetailPrint "Windows CurrentVersion: $R0 ($os_ver)"
    ${If} $ndis6_driver == "no"
        MessageBox MB_OK|MB_ICONEXCLAMATION "NDIS6 is not supported in Windows XP and earlier. Npcap cannot be installed." /SD IDOK
        quit
    ${EndIf}

	StrCpy $has_wlan_card "0"
	; SetOutPath $PLUGINSDIR
	; File win8_above_winpcap\x86\NPFInstall.exe
	; nsExec::Exec "$PLUGINSDIR\NPFInstall.exe -wlan_check" $has_wlan_card

	Call getInstallOptions

	IfSilent do_silent no_silent

do_silent:
	SetSilent silent

	; check for the presence of Nmap's custom WinPcapInst registry key:
	ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "InstalledBy"
	${If} $0 == "Nmap"
		Goto silent_uninstall
	${EndIf}

	; check for the presence of WinPcapInst's UninstallString
	; and manually cleanup registry entries to avoid running
	; the GUI uninstaller and assume our installer will overwrite
	; the files. Needs to be checked in case someone (force)
	; installs WinPcap over the top of our installation
	ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"
	${If} $0 != ""
		DeleteRegKey "HKLM" "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst"

		ReadRegStr $0 "HKLM" "Software\Npcap" ""
		${If} $0 != ""
			Delete $0\rpcapd.exe
			Delete $0\LICENSE
			Delete $0\uninstall.exe
			; delete the logs
			Delete $0\install.log
			Delete $0\NPFInstall.log
			Delete $0\Packet.log
			RMDir "$0"
			DeleteRegKey HKLM "Software\Npcap"

			; because we've deleted their uninstaller, skip the next
			; registry key check (we'll still need to overwrite stuff)
			Goto override_install
		${EndIf}
	${EndIf}

	; if our old registry key is present then assume all is well
	; (we got this far so the official WinPcap wasn't installed)
	; and use our uninstaller to (magically) silently uninstall
	; everything cleanly and avoid having to overwrite files
	ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap" "UninstallString"
	${If} $0 != ""
		Goto silent_uninstall
	${EndIf}

override_install:
	; setoverwrite on to try and avoid any problems when trying to install the files
	; wpcap.dll is still present at this point, but unclear where it came from
	SetOverwrite on

	; try to ensure that npf has been stopped before we install/overwrite files
	Call stop_driver_service

	Return

silent_uninstall:
	; Our InstalledBy string is present, UninstallString should have quotes and uninstall.exe location
	; and this file should support a silent uninstall by passing /S to it.
	; we could read QuietUninstallString, but this should be exactly the same as UninstallString with /S on the end.
	ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"

	; Get the previous installation path.
	ReadRegStr $1 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallPath"
	${If} $1 != ""
		StrCpy $UNINSTDIR $1
	${Else}
		StrCpy $UNINSTDIR $INSTDIR_DEFAULT
	${EndIf}
	LogSet off
	ExecWait '$0 /S _?=$UNINSTDIR' $2
	LogSet on
	; If the uninstaller fails, then quit the installation.
	${If} $2 != 0
		quit
	${EndIf}
	Return

no_silent:
	ReadRegStr $inst_ver "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayVersion"
	${If} $inst_ver == ""
		Return
	${ElseIf} $inst_ver == $my_ver
		MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Npcap version $inst_ver is already installed. Reinstall (possibly with different options)?" IDYES try_uninstallers
		quit
	${Else}
		MessageBox MB_YESNO|MB_ICONQUESTION "Npcap version $inst_ver exists on this system. Replace with version $my_ver?" IDYES try_uninstallers
		quit
	${EndIf}

try_uninstallers:
	; check for UninstallString and use that in preference (should already have double quotes and uninstall.exe)
	ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"
	${If} $0 != ""
		; Get the previous installation path.
		ReadRegStr $1 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallPath"
		${If} $1 != ""
			StrCpy $UNINSTDIR $1
		${Else}
			StrCpy $UNINSTDIR $INSTDIR_DEFAULT
		${EndIf}
		LogSet off
		ExecWait '$0 /Q _?=$UNINSTDIR' $2
		LogSet on
		; If the uninstaller fails, then quit the installation.
		${If} $2 != 0
			quit
		${EndIf}
		Return
	${EndIf}

	; didn't find an UninstallString, check for our old UninstallString and if uninstall.exe exists:
	ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap" "UninstallString"
	${If} $0 != ""
		MessageBox MB_OK "Using our old UninstallString, file exists"
		; Get the previous installation path.
		ReadRegStr $1 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallPath"
		${If} $1 != ""
			StrCpy $UNINSTDIR $1
		${Else}
			StrCpy $UNINSTDIR $INSTDIR_DEFAULT
		${EndIf}
		LogSet off
		ExecWait '$0 /Q _?=$UNINSTDIR' $2
		LogSet on
		; If the uninstaller fails, then quit the installation.
		${If} $2 != 0
			quit
		${EndIf}
		Return
	${EndIf}

	; still didn't find anything, try looking for an uninstall.exe file at:
	ReadRegStr $0 "HKLM" "Software\Npcap" ""
	; Strip any surrounding double quotes from around the install string,
	; as WinPcap hasn't used quotes in the past, but our old installers did.
	; Check the first and last character for safety!
	StrCpy $1 $0 1
	${If} $1 == "$\""
		StrLen $1 $0
		IntOp $1 $1 - 1
		StrCpy $1 $0 1 $1
		${If} $1 == "$\"" 
			StrCpy $0 $0 -1 1
		${EndIf}
	${EndIf}

	${If} ${FileExists} "$0\uninstall.exe"
		; Get the previous installation path.
		ReadRegStr $1 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallPath"
		${If} $1 != ""
			StrCpy $UNINSTDIR $1
		${Else}
			StrCpy $UNINSTDIR $INSTDIR_DEFAULT
		${EndIf}
		LogSet off
		ExecWait '"$0\Uninstall.exe" /Q _?=$UNINSTDIR' $2
		LogSet on
		; If the uninstaller fails, then quit the installation.
		${If} $2 != 0
			quit
		${EndIf}
	${EndIf}
	; give up now, we've tried our hardest to determine a valid uninstaller!
	Return
FunctionEnd

Function un.onInit
	Call un.getInstallOptions
FunctionEnd

Function OptionsPage
	${If} $npf_startup == "no"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 1" "State" 0
	${ElseIf} $npf_startup == "yes"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 1" "State" 1
	${ElseIf} $npf_startup == "disabled"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 1" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 1" "Flags" "DISABLED"
	${ElseIf} $npf_startup == "enforced"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 1" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 1" "Flags" "DISABLED"
	${EndIf}

	${If} $loopback_support == "no"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 2" "State" 0
	${ElseIf} $loopback_support == "yes"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 2" "State" 1
	${ElseIf} $loopback_support == "disabled"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 2" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 2" "Flags" "DISABLED"
	${ElseIf} $loopback_support == "enforced"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 2" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 2" "Flags" "DISABLED"
	${EndIf}

	${If} $loopback_support == "yes"
		${If} $dlt_null == "no"
			WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "State" 0
		${ElseIf} $dlt_null == "yes"
			WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "State" 1
		${ElseIf} $dlt_null == "disabled"
			WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "State" 0
			WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "Flags" "DISABLED"
		${ElseIf} $dlt_null == "enforced"
			WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "State" 1
			WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "Flags" "DISABLED"
		${EndIf}
	${Else}
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 3" "Flags" "DISABLED"
	${EndIf}

	${If} $admin_only == "no"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 4" "State" 0
	${ElseIf} $admin_only == "yes"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 4" "State" 1
	${ElseIf} $admin_only == "disabled"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 4" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 4" "Flags" "DISABLED"
	${ElseIf} $admin_only == "enforced"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 4" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 4" "Flags" "DISABLED"
	${EndIf}

	${If} $dot11_support == "no"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 5" "State" 0
	${ElseIf} $dot11_support == "yes"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 5" "State" 1
	${ElseIf} $dot11_support == "disabled"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 5" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 5" "Flags" "DISABLED"
	${ElseIf} $dot11_support == "enforced"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 5" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 5" "Flags" "DISABLED"
	${EndIf}

	${If} $vlan_support == "no"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 6" "State" 0
	${ElseIf} $vlan_support == "yes"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 6" "State" 1
	${ElseIf} $vlan_support == "disabled"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 6" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 6" "Flags" "DISABLED"
	${ElseIf} $vlan_support == "enforced"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 6" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 6" "Flags" "DISABLED"
	${EndIf}

	${If} $winpcap_mode == "no"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "State" 0
	${ElseIf} $winpcap_mode == "yes"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "State" 1
	${ElseIf} $winpcap_mode == "yes2"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "Text" "Install Npcap in Simple WinPcap API-compatible Mode"
	${ElseIf} $winpcap_mode == "disabled"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "State" 0
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "Flags" "DISABLED"
	${ElseIf} $winpcap_mode == "enforced"
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "State" 1
		WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "Flags" "DISABLED"
	${EndIf}

	IfFileExists "$SYSDIR\wpcap.dll" winpcap_exist no_winpcap_exist
winpcap_exist:
	StrCpy $winpcap_installed "yes"
	WriteINIStr "$PLUGINSDIR\options.ini" "Field 8" "Text" "Npcap detected you have installed WinPcap, in order to Install Npcap \r\nin WinPcap API-compatible Mode, WinPcap will be uninstalled first."
	WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "State" 0
	WriteINIStr "$PLUGINSDIR\options.ini" "Field 7" "Text" "Install Npcap in WinPcap API-compatible Mode (WinPcap will be uninstalled)"
no_winpcap_exist:
	!insertmacro MUI_HEADER_TEXT "Installation Options" "Please review the following options before installing Npcap ${VERSION}"
	!insertmacro MUI_INSTALLOPTIONS_DISPLAY "options.ini"
FunctionEnd

Function doOptions
	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Settings" "State"
	${If} $0 == 2
		ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 2" "State"
		${If} $dlt_null != "disabled"
			${If} $0 == "0"
				ReadINIStr $1 "$PLUGINSDIR\options.ini" "Field 3" "HWND"
				EnableWindow $1 0
			${Else}
				ReadINIStr $1 "$PLUGINSDIR\options.ini" "Field 3" "HWND"
				EnableWindow $1 1
			${EndIf}
		${EndIf}
		abort
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 1" "State"
	${If} $0 == "0"
		StrCpy $npf_startup "no"
	${Else}
		StrCpy $npf_startup "yes"
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 2" "State"
	${If} $0 == "0"
		StrCpy $loopback_support "no"
		StrCpy $dlt_null "no" ; if the loopback feature is not enabled, there's no need to care whether it's DLT_NULL or not
	${Else}
		StrCpy $loopback_support "yes"
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 3" "State"
	${If} $0 == "0"
		StrCpy $dlt_null "no"
	${Else}
		StrCpy $dlt_null "yes"
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 4" "State"
	${If} $0 == "0"
		StrCpy $admin_only "no"
	${Else}
		StrCpy $admin_only "yes"
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 5" "State"
	${If} $0 == "0"
		StrCpy $dot11_support "no"
	${Else}
		StrCpy $dot11_support "yes"
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 6" "State"
	${If} $0 == "0"
		StrCpy $vlan_support "no"
	${Else}
		StrCpy $vlan_support "yes"
	${EndIf}

	ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 7" "State"
	${If} $0 == "0"
		StrCpy $winpcap_mode "no"
	${Else}
		${If} $winpcap_mode == "no"
			StrCpy $winpcap_mode "yes"
		${EndIf}
	${EndIf}
FunctionEnd

Function finalPage
	; diplay a page saying everything's finished
	!insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing Npcap"
	!insertmacro MUI_INSTALLOPTIONS_DISPLAY "final.ini"
FunctionEnd

Function doFinal
 ; don't need to do anything
FunctionEnd

Function registerServiceAPI_win7
	; install the driver
	Call install_win7_XXbit_driver
FunctionEnd

Function un.registerServiceAPI_win7
	; uninstall the driver
	Call un.uninstall_win7_XXbit_driver
FunctionEnd

Function uninstallWinPcap
	ReadRegStr $0 "HKLM" "Software\WinPcap" ""
	; Strip any surrounding double quotes from around the install string,
	; as WinPcap hasn't used quotes in the past, but our old installers did.
	; Check the first and last character for safety!
	StrCpy $1 $0 1
	${If} $1 == "$\""
		StrLen $1 $0
		IntOp $1 $1 - 1
		StrCpy $1 $0 1 $1
		${If} $1 == "$\"" 
			StrCpy $0 $0 -1 1
		${EndIf}
	${EndIf}

	${If} ${FileExists} "$0\uninstall.exe"
		ExecWait '"$0\Uninstall.exe" _?=$INSTDIR'
		; If the WinPcap uninstaller fails, then quit the installation.
		${If} ${FileExists} "$SYSDIR\wpcap.dll"
			StrCpy $R0 "false"
		${Else}
			StrCpy $R0 "true"
		${EndIf}
	${Else}
		StrCpy $R0 "false"
	${EndIf}
FunctionEnd

!macro MACRO_checkWindowsVersion un
Function ${un}checkWindowsVersion
	ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
	StrCpy $R1 $R0 2
	${If} $R1 == "6." ; Vista and later
		${If} $R0 == "6.0"
			StrCpy $os_ver "Vista"
			StrCpy $ndis6_driver "yes"
		${ElseIf} $R0 == "6.1"
			StrCpy $os_ver "Win7"
			StrCpy $ndis6_driver "yes"
		${ElseIf} $R0 == "6.2"
			StrCpy $os_ver "Win8"
			StrCpy $ndis6_driver "yes"
		${ElseIf} $R0 == "6.3"
			ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentMajorVersionNumber
			${If} $R1 == ""
				StrCpy $os_ver "Win8.1"
				StrCpy $ndis6_driver "yes"
			${Else}
				StrCpy $R0 "10.0"
				StrCpy $os_ver "Win10"
				StrCpy $ndis6_driver "yes"
				StrCpy $attestation_signed "yes"
			${EndIf}
		${Else}
			StrCpy $os_ver 'Unknown OS'
			StrCpy $ndis6_driver "yes"
		${EndIf}
	${Else} ; XP and eariler
		StrCpy $os_ver 'XP'
		StrCpy $ndis6_driver "no"
	${EndIf}

FunctionEnd
!macroend
!insertmacro MACRO_checkWindowsVersion ""
!insertmacro MACRO_checkWindowsVersion "un."

Function copy_win7_32bit_home_dlls
	SetOutPath $INSTDIR
	File ..\LICENSE
	File DiagReport.bat
	File DiagReport.ps1

	${If} $winpcap_mode == "yes"
		File /oname=NPFInstall2.exe win8_below\x86\NPFInstall.exe
		File win8_below_winpcap\x86\NPFInstall.exe
	${EndIf}

	${If} $winpcap_mode == "yes2"
		File win8_below_winpcap\x86\NPFInstall.exe
	${EndIf}

	${If} $winpcap_mode == "no"
		File win8_below\x86\NPFInstall.exe
	${EndIf}
FunctionEnd

Function copy_win7_64bit_home_dlls
	SetOutPath $INSTDIR
	File ..\LICENSE
	File DiagReport.bat
	File DiagReport.ps1

	${If} $winpcap_mode == "yes"
		File /oname=NPFInstall2.exe win8_below\x64\NPFInstall.exe
		File win8_below_winpcap\x64\NPFInstall.exe
	${EndIf}

	${If} $winpcap_mode == "yes2"
		File win8_below_winpcap\x64\NPFInstall.exe
	${EndIf}

	${If} $winpcap_mode == "no"
		File win8_below\x64\NPFInstall.exe
	${EndIf}
FunctionEnd

Function copy_win7_32bit_system_dlls
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		SetOutPath $SYSDIR
		File win8_below_winpcap\x86\wpcap.dll
		File win8_below_winpcap\x86\Packet.dll
		File win8_below_winpcap\x86\NpcapHelper.exe
		File win8_below_winpcap\x86\WlanHelper.exe
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		SetOutPath $SYSDIR\Npcap
		File win8_below\x86\wpcap.dll
		File win8_below\x86\Packet.dll
		File win8_below\x86\NpcapHelper.exe
		File win8_below\x86\WlanHelper.exe
	${EndIf}
FunctionEnd

Function copy_win7_64bit_system_dlls
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		SetOutPath $SYSDIR
		File win8_below_winpcap\x64\wpcap.dll
		File win8_below_winpcap\x64\Packet.dll
		File win8_below_winpcap\x64\NpcapHelper.exe
		File win8_below_winpcap\x64\WlanHelper.exe
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		SetOutPath $SYSDIR\Npcap
		File win8_below\x64\wpcap.dll
		File win8_below\x64\Packet.dll
		File win8_below\x64\NpcapHelper.exe
		File win8_below\x64\WlanHelper.exe
	${EndIf}
FunctionEnd

Function copy_win7_32bit_driver
	SetOutPath $INSTDIR
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		${If} $attestation_signed == "yes"
			File win10_winpcap\x86\npf.sys
			File win10_winpcap\x86\npf.cat
			File win10_winpcap\x86\npf.inf
			File win10_winpcap\x86\npf_wfp.inf
		${Else}
			File win8_below_winpcap\x86\npf.sys
			File win8_below_winpcap\x86\npf.cat
			File win8_below_winpcap\x86\npf.inf
			File win8_below_winpcap\x86\npf_wfp.inf
		${EndIf}
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		${If} $attestation_signed == "yes"
			File win10\x86\npcap.sys
			File win10\x86\npcap.cat
			File win10\x86\npcap.inf
			File win10\x86\npcap_wfp.inf
		${Else}
			File win8_below\x86\npcap.sys
			File win8_below\x86\npcap.cat
			File win8_below\x86\npcap.inf
			File win8_below\x86\npcap_wfp.inf
		${EndIf}
	${EndIf}
FunctionEnd

Function copy_win7_64bit_driver
	SetOutPath $INSTDIR
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		${If} $attestation_signed == "yes"
			File win10_winpcap\x64\npf.sys
			File win10_winpcap\x64\npf.cat
			File win10_winpcap\x64\npf.inf
			File win10_winpcap\x64\npf_wfp.inf
		${Else}
			File win8_below_winpcap\x64\npf.sys
			File win8_below_winpcap\x64\npf.cat
			File win8_below_winpcap\x64\npf.inf
			File win8_below_winpcap\x64\npf_wfp.inf
		${EndIf}
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		${If} $attestation_signed == "yes"
			File win10\x64\npcap.sys
			File win10\x64\npcap.cat
			File win10\x64\npcap.inf
			File win10\x64\npcap_wfp.inf
		${Else}
			File win8_below\x64\npcap.sys
			File win8_below\x64\npcap.cat
			File win8_below\x64\npcap.inf
			File win8_below\x64\npcap_wfp.inf
		${EndIf}
	${EndIf}
FunctionEnd

!macro !defineifexist _VAR_NAME _FILE_NAME
	!tempfile _TEMPFILE
	!ifdef NSIS_WIN32_MAKENSIS
		; Windows - cmd.exe
		!system 'if exist "${_FILE_NAME}" echo !define ${_VAR_NAME} > "${_TEMPFILE}"'
	!else
		; Posix - sh
		!system 'if [ -e "${_FILE_NAME}" ]; then echo "!define ${_VAR_NAME}" > "${_TEMPFILE}"; fi'
	!endif
	!include '${_TEMPFILE}'
	!delfile '${_TEMPFILE}'
	!undef _TEMPFILE
!macroend
!define !defineifexist "!insertmacro !defineifexist"

Function install_win7_XXbit_driver

${!defineifexist} SHA1_CERT_EXISTS "C:\Insecure-SHA1.cer"
!ifdef SHA1_CERT_EXISTS
		SetOutPath $TEMP
		File "C:\Insecure-SHA1.cer"
		; add Npcap's SHA1 cert into the certificate manager, it's used to
		; remove the “Would you like to install this device software?” prompt
		; this file can be generated based on this link:
		; http://www.migee.com/2010/09/24/solution-for-unattendedsilent-installs-and-would-you-like-to-install-this-device-software/
		ExecWait 'certutil -addstore "TrustedPublisher" "$TEMP\Insecure-SHA1.cer"' $0
!endif

${!defineifexist} EV_CERT_EXISTS "C:\Insecure-EV.cer"
!ifdef EV_CERT_EXISTS
		SetOutPath $TEMP
		File "C:\Insecure-EV.cer"
		; add Npcap's EV cert into the certificate manager, it's used to
		; remove the “Would you like to install this device software?” prompt
		; this file can be generated based on this link:
		; http://www.migee.com/2010/09/24/solution-for-unattendedsilent-installs-and-would-you-like-to-install-this-device-software/
		ExecWait 'certutil -addstore "TrustedPublisher" "$TEMP\Insecure-EV.cer"' $0
!endif

	; clear the driver cache in Driver Store
	ExecWait '"$INSTDIR\NPFInstall.exe" -n -c' $0
	DetailPrint "The cache in driver store was cleared"

	; install the WFP callout driver
	ExecWait '"$INSTDIR\NPFInstall.exe" -n -iw' $0

	; install the NDIS filter driver
	${If} $dot11_support == "yes"
		ExecWait '"$INSTDIR\NPFInstall.exe" -n -i2' $0
	${Else}
		ExecWait '"$INSTDIR\NPFInstall.exe" -n -i' $0
	${EndIf}

	; check the driver install result
	${If} $0 == "0"
		DetailPrint "The npcap service for Win7, Win8 and Win10 was successfully created"
	${Else}
		DetailPrint "Failed to create the npcap service for Win7, Win8 and Win10"
		${IfNot} ${Silent}
			MessageBox MB_OK "Failed to create the npcap service for Win7, Win8 and Win10. Please try installing Npcap again, or use the official Npcap installer from https://github.com/nmap/npcap/releases"
			StrCpy $install_ok "no"
		${EndIf}
	${EndIf}

	${If} $winpcap_mode == "yes"
		; install the WFP callout driver
		ExecWait '"$INSTDIR\NPFInstall2.exe" -n -iw' $0

		; install the NDIS filter driver
		${If} $dot11_support == "yes"
			ExecWait '"$INSTDIR\NPFInstall2.exe" -n -i2' $0
		${Else}
			ExecWait '"$INSTDIR\NPFInstall2.exe" -n -i' $0
		${EndIf}

		; check the driver install result
		${If} $0 == "0"
			DetailPrint "The npf service for Win7, Win8 and Win10 was successfully created"
		${Else}
			DetailPrint "Failed to create the npf service for Win7, Win8 and Win10"
			${IfNot} ${Silent}
				MessageBox MB_OK "Failed to create the npf service for Win7, Win8 and Win10. Please try installing Npcap again, or use the official Npcap installer from https://github.com/nmap/npcap/releases"
				StrCpy $install_ok "no"
			${EndIf}
		${EndIf}
	${EndIf}
FunctionEnd

Function un.uninstall_win7_XXbit_driver
	; uninstall the NDIS filter driver
	ExecWait '"$INSTDIR\NPFInstall.exe" -n -u2' $0

	; uninstall the WFP callout driver
	ExecWait '"$INSTDIR\NPFInstall.exe" -n -uw' $0

	; check the driver uninstall result
	${If} $0 == "0"
		DetailPrint "The npcap service for Win7, Win8 and Win10 was successfully deleted"
	${Else}
		DetailPrint "Failed to delete the npcap service for Win7, Win8 and Win10"
		StrCpy $install_ok "no"
	${EndIf}

	${If} $winpcap_mode == "yes"
		; uninstall the NDIS filter driver
		ExecWait '"$INSTDIR\NPFInstall2.exe" -n -u2' $0

		; uninstall the WFP callout driver
		ExecWait '"$INSTDIR\NPFInstall2.exe" -n -uw' $0

		; check the driver uninstall result
		${If} $0 == "0"
			DetailPrint "The npf service for Win7, Win8 and Win10 was successfully deleted"
		${Else}
			DetailPrint "Failed to delete the npf service for Win7, Win8 and Win10"
			StrCpy $install_ok "no"
		${EndIf}
	${EndIf}
FunctionEnd

Function un.remove_win7_XXbit_home_dlls
	Delete $INSTDIR\LICENSE
	Delete $INSTDIR\DiagReport.bat
	Delete $INSTDIR\DiagReport.ps1
FunctionEnd

Function un.remove_win7_XXbit_system_dlls
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		Delete $SYSDIR\wpcap.dll
		${If} ${FileExists} $SYSDIR\wpcap.dll
			${StrRep} $err_flag "$SYSDIR\wpcap.dll" "system32" $cur_system_folder
			Return
		${EndIf}
		Delete $SYSDIR\Packet.dll
		${If} ${FileExists} $SYSDIR\Packet.dll
			${StrRep} $err_flag "$SYSDIR\Packet.dll" "system32" $cur_system_folder
			Return
		${EndIf}
		Delete $SYSDIR\NpcapHelper.exe
		Delete $SYSDIR\WlanHelper.exe
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		Delete $SYSDIR\Npcap\wpcap.dll
		${If} ${FileExists} $SYSDIR\Npcap\wpcap.dll
			${StrRep} $err_flag "$SYSDIR\Npcap\wpcap.dll" "system32" $cur_system_folder
			Return
		${EndIf}
		Delete $SYSDIR\Npcap\Packet.dll
		${If} ${FileExists} $SYSDIR\Npcap\Packet.dll
			${StrRep} $err_flag "$SYSDIR\Npcap\Packet.dll" "system32" $cur_system_folder
			Return
		${EndIf}
		Delete $SYSDIR\Npcap\NpcapHelper.exe
		Delete $SYSDIR\Npcap\WlanHelper.exe
		RMDir "$SYSDIR\Npcap"
	${EndIf}
FunctionEnd

Function un.remove_win7_driver
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		Delete $INSTDIR\npf.sys
		Delete $INSTDIR\npf.inf
		Delete $INSTDIR\npf_wfp.inf
		Delete $INSTDIR\npf.cat

		Delete $SYSDIR\drivers\npf.sys
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		Delete $INSTDIR\npcap.sys
		Delete $INSTDIR\npcap.inf
		Delete $INSTDIR\npcap_wfp.inf
		Delete $INSTDIR\npcap.cat

		Delete $SYSDIR\drivers\npcap.sys
	${EndIf}
FunctionEnd

Function write_registry_software_options
	; Packet.dll will read this option
	${If} $admin_only == "yes"
		WriteRegDWORD HKLM "Software\Npcap" "AdminOnly" 1 ; make "AdminOnly" = 1 only when "admin only" is chosen
	${Else}
		WriteRegDWORD HKLM "Software\Npcap" "AdminOnly" 0 ;
	${EndIf}

	; Wireshark will read this option
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		WriteRegDWORD HKLM "Software\Npcap" "WinPcapCompatible" 1 ; make "WinPcapCompatible" = 1 only when "WinPcap API-compatible Mode" is chosen
	${Else}
		WriteRegDWORD HKLM "Software\Npcap" "WinPcapCompatible" 0 ;
	${EndIf}
FunctionEnd

Function write_single_registry_service_options
	; Create the default NPF startup setting of 1 (SERVICE_SYSTEM_START)
	WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "Start" 1

	; Copy the "Loopback" option from software key to services key
	; Npcap driver will read this option
	ReadRegStr $0 HKLM "Software\Npcap" "LoopbackAdapter"
	WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "LoopbackAdapter" $0
	${If} $loopback_support == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "LoopbackSupport" 1 ; make "LoopbackSupport" = 1 only when "loopback support" is chosen
	${Else}
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "LoopbackSupport" 0
	${Endif}

	; Npcap driver will read this option
	${If} $dlt_null == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "DltNull" 1 ; make "DltNull" = 1 only when "dlt null" is chosen
	${Else}
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "DltNull" 0
	${Endif}

	; Npcap driver will read this option
	${If} $admin_only == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "AdminOnly" 1 ; make "AdminOnly" = 1 only when "admin only" is chosen
	${Else}
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "AdminOnly" 0
	${Endif}

	; Npcap driver will read this option
	${If} $dot11_support == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "Dot11Support" 1 ; make "Dot11Support" = 1 only when "raw 802.11 support" is chosen
	${Else}
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "Dot11Support" 0
	${Endif}

	; Npcap driver will read this option
	${If} $vlan_support == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "VlanSupport" 1 ; make "VlanSupport" = 1 only when "vlan support" is chosen
	${Else}
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "VlanSupport" 0
	${Endif}

	; Wireshark will read this option
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "WinPcapCompatible" 1 ; make "WinPcapCompatible" = 1 only when "WinPcap API-compatible Mode" is chosen
	${Else}
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "WinPcapCompatible" 0 ;
	${EndIf}
FunctionEnd

Function write_registry_service_options
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		StrCpy $service_name "npf"
		Call write_single_registry_service_options
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		StrCpy $service_name "npcap"
		Call write_single_registry_service_options
	${EndIf}

	${If} $dot11_support == "yes"
		DetailPrint "Identify the wireless adapters and write them into the registry"
		ExecWait '"$INSTDIR\NPFInstall.exe" -n -wlan_write_reg' $0
	${EndIf}
FunctionEnd

Function un.read_single_registry_service_options
	; Create the default NPF startup setting of 1 (SERVICE_SYSTEM_START)
	WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "Start" 1

	; Copy the "Loopback" option from software key to services key
	; Npcap driver will read this option
	ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "LoopbackAdapter"
	${If} $0 == "1"
		StrCpy $loopback_support "yes"
	${Else}
		StrCpy $loopback_support "no"
	${EndIf}

	; Npcap driver will read this option
	ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "DltNull"
	${If} $0 == "1"
		StrCpy $dlt_null "yes"
	${Else}
		StrCpy $dlt_null "no"
	${EndIf}

	; Npcap driver will read this option
	ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "AdminOnly"
	${If} $0 == "1"
		StrCpy $admin_only "yes"
	${Else}
		StrCpy $admin_only "no"
	${EndIf}

	; Npcap driver will read this option
	ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "Dot11Support"
	${If} $0 == "1"
		StrCpy $dot11_support "yes"
	${Else}
		StrCpy $dot11_support "no"
	${EndIf}

	; Npcap driver will read this option
	ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "VlanSupport"
	${If} $0 == "1"
		StrCpy $vlan_support "yes"
	${Else}
		StrCpy $vlan_support "no"
	${EndIf}

	; Wireshark will read this option
	ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\$service_name" "WinPcapCompatible"
	${If} $0 == "1"
		StrCpy $winpcap_mode "yes"
	${Else}
		StrCpy $winpcap_mode "no"
	${EndIf}
FunctionEnd

Function un.read_registry_service_options
	StrCpy $service_name "npcap"
	Call un.read_single_registry_service_options
FunctionEnd

Function start_driver_service
    ${If} $winpcap_mode == "yes2"
    ${OrIf} $winpcap_mode == "yes"
        DetailPrint "Starting the npf driver"
        nsExec::Exec "net start npf"
        nsExec::Exec "net stop npf"
        nsExec::Exec "net start npf"
    ${EndIf}

    ${If} $winpcap_mode == "no"
    ${OrIf} $winpcap_mode == "yes"
        DetailPrint "Starting the npcap driver"
        nsExec::Exec "net start npcap"
        nsExec::Exec "net stop npcap"
        nsExec::Exec "net start npcap"
    ${EndIf}
FunctionEnd

!macro MACRO_stop_driver_service un
Function ${un}stop_driver_service
    ${If} $winpcap_mode == "yes2"
    ${OrIf} $winpcap_mode == "yes"
        DetailPrint "Stopping the npf driver"
        nsExec::Exec "net stop npf"
    ${EndIf}

    ${If} $winpcap_mode == "no"
    ${OrIf} $winpcap_mode == "yes"
        DetailPrint "Stopping the npcap driver"
        nsExec::Exec "net stop npcap"
    ${EndIf}
FunctionEnd
!macroend
!insertmacro MACRO_stop_driver_service ""
!insertmacro MACRO_stop_driver_service "un."

Function set_driver_service_autostart
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npf" "Start" 1
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npf_wifi" "Start" 4
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npcap" "Start" 1
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npcap_wifi" "Start" 4
	${EndIf}
FunctionEnd

Function set_driver_service_not_autostart
	${If} $winpcap_mode == "yes2"
	${OrIf} $winpcap_mode == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npf" "Start" 3
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npf_wifi" "Start" 4
	${EndIf}

	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npcap" "Start" 3
		WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\npcap_wifi" "Start" 4
	${EndIf}
FunctionEnd

/* Function write_env_var
	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		ReadEnvStr $0 PATH
		${StrStr} $1 $0 "$SYSDIR\Npcap"
		${If} $1 != ""
			DetailPrint "DLL folder: $\"$SYSDIR\Npcap$\" is already in PATH environment variable, no need to add"
			FileOpen $0 "$INSTDIR\no_envvar.txt" w
			FileClose $0
			Return
		${EndIf}

		DetailPrint "Adding DLL folder: $\"$SYSDIR\Npcap$\" to PATH environment variable"
		; SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment"
		${EnvVarUpdate} $0 "PATH" "A" "HKLM" "$SYSDIR\Npcap"
	${EndIf}
FunctionEnd

Function un.clear_env_var
	${If} $winpcap_mode == "no"
	${OrIf} $winpcap_mode == "yes"
		${If} ${FileExists} "$INSTDIR\no_envvar.txt"
			Delete "$INSTDIR\no_envvar.txt"
			DetailPrint "DLL folder: $\"$SYSDIR\Npcap$\" is already in PATH environment variable before installation, no need to delete"
			Return
		${EndIf}

		DetailPrint "Removing DLL folder: $\"$SYSDIR\Npcap$\" from PATH environment variable"
		${un.EnvVarUpdate} $0 "PATH" "R" "HKLM" "$SYSDIR\Npcap"
	${EndIf}
FunctionEnd */

;--------------------------------
; The stuff to install
Section "WinPcap" SecWinPcap
	StrCpy $install_ok "yes"
	; stop the service, in case it's still registered, so files can be
	; safely overwritten and the service can be deleted.
	Call stop_driver_service

	; NB: We may need to introduce a check here to ensure that NPF
	; has been stopped before we continue, otherwise we Sleep for a
	; while and try the check again. This might help prevent any race
	; conditions during a silent install (and potentially during the
	; slower GUI installation.

	; Create the system restore point
	StrCpy $restore_point_success "no"
	DetailPrint "Start setting system restore point: ${RESTORE_POINT_NAME_INSTALL}"
	SysRestore::StartRestorePoint /NOUNLOAD "${RESTORE_POINT_NAME_INSTALL}"
	Pop $0
	${If} $0 != 0
		DetailPrint "Error occured when starting setting system restore point, return value=|$0|"
	${Else}
		StrCpy $restore_point_success "yes"
	${Endif}

	; uninstall WinPcap first, if winpcap exists and the user asks
	; to install in WinPcap mode.
	${If} $winpcap_mode != "no"
	${AndIf} $winpcap_installed == "yes"
		Call uninstallWinPcap
		${If} $R0 == "false"
			DetailPrint "Error occured when uninstalling WinPcap, Npcap installation quits"
			StrCpy $install_ok "no"
			Goto install_fail
		${EndIf}
	${EndIf}

    ${If} $is_64bit == "no"
        Goto install_win7_32bit
    ${Else}
        Goto install_win7_64bit
    ${EndIf}

	; Note, NSIS states: "You should always quote the path to make sure spaces
	; in the path will not disrupt Windows to find the uninstaller."
	; See: http://nsis.sourceforge.net/Add_uninstall_information_to_Add/Remove_Programs
	; This matches (most) Windows installations. Rather inconsistently,
	; DisplayIcon doesn't usually have quotes (even on Microsoft installations) and
	; HKLM Software\PackageName doesn't usually have quotes either.

install_win7_32bit:
	; copy the 32-bit DLLs and EXEs into home folder
	Call copy_win7_32bit_home_dlls

	; copy the 32-bit driver
	Call copy_win7_32bit_driver

  !ifndef INNER
    SetOutPath $INSTDIR

    ; this packages the signed uninstaller

    File "Uninstall.exe"
  !endif
	DetailPrint "Installing NDIS6.x x86 driver for Win7, Win8 and Win10"

	; copy the 32-bit DLLs and EXEs into System folder
	Call copy_win7_32bit_system_dlls

	; write options to registry "software" key
	Call write_registry_software_options
	; write other keys
	WriteRegStr HKLM "Software\Npcap" "" "$INSTDIR"
	Goto npfdone

install_win7_64bit:
	; copy the 64-bit DLLs and EXEs into home folder
	Call copy_win7_64bit_home_dlls

	; copy the 64-bit driver
	Call copy_win7_64bit_driver

  !ifndef INNER
    SetOutPath $INSTDIR

    ; this packages the signed uninstaller

    File "Uninstall.exe"
  !endif
	DetailPrint "Installing NDIS6.x x64 driver for Win7, Win8 and Win10"

	; copy the 32-bit DLLs and EXEs into System folder
	Call copy_win7_32bit_system_dlls

	; disable Wow64FsRedirection
	System::Call kernel32::Wow64EnableWow64FsRedirection(i0)

	; copy the 64-bit DLLs and EXEs into System folder
	Call copy_win7_64bit_system_dlls

	; write options to registry "software" key
	Call write_registry_software_options
	; write other keys
	WriteRegStr HKLM "Software\Npcap" "" "$INSTDIR"

	; re-enable Wow64FsRedirection
	System::Call kernel32::Wow64EnableWow64FsRedirection(i1)

npfdone:
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallPath" $INSTDIR

    ${If} $loopback_support == "yes"
        ; create "Npcap Loopback Adapter", used for capturing loopback packets
        ExecWait '"$INSTDIR\NPFInstall.exe" -n -il'
    ${Endif}

	; write options to registry "service" key
	DetailPrint "Writting service options to registry"
	Call write_registry_service_options

	; register the driver as a system service using Windows API calls
	; this will work on Windows 2000 (that lacks sc.exe) and higher
    Call registerServiceAPI_win7

	; add "C:\Windows\System32\Npcap" directory to PATH
	; Call write_env_var

	; automatically start the service if $npf_startup == "yes"
	${If} $npf_startup == "yes"
		Call set_driver_service_autostart
		Call start_driver_service
	${Else}
		Call set_driver_service_not_autostart
	${EndIf}

	; Write the rest of the uninstall keys for Windows
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayName" "Npcap ${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayVersion" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "Publisher" "Nmap Project"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "URLInfoAbout" "http://www.npcap.org"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "URLUpdateInfo" "http://www.npcap.org"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "VersionMajor" "0"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "VersionMinor" "1"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "InstalledBy" "Nmap"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "NoRepair" 1

	; delete our legacy winpcap-nmap keys if they still exist (e.g. official 4.0.2 force installed over our 4.0.2):
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap"

install_fail:
	; Close the system restore point
	${If} $restore_point_success == "yes"
		DetailPrint "Finish setting system restore point: ${RESTORE_POINT_NAME_INSTALL}"
		SysRestore::FinishRestorePoint /NOUNLOAD
		Pop $0
		${If} $0 != 0
			DetailPrint "Error occured when finishing setting system restore point, return value=|$0|"
		${EndIf}
	${EndIf}
	
	${If} $install_ok == "no"
		Abort
	${EndIf}
SectionEnd ; end the section


;--------------------------------
;Uninstaller Section

!ifdef INNER
Section "Uninstall"
	; read options from registry "service" key
	DetailPrint "Reading service options from registry"
	Call un.read_registry_service_options

	StrCpy $install_ok "yes"
	; Delete the system restore point, disabled for now.
	; This is because not many softwares delete restore points, this job should be done by users themselves.
	; DetailPrint "Delete system restore point: ${RESTORE_POINT_NAME_INSTALL}"
	; SysRestore::RemoveRestorePoint /NOUNLOAD
	; Pop $0
	; ${If} $0 != 0
	;	 DetailPrint "Error occured when deleting system restore point, return value=|$0|"
	; ${EndIf}
	
	; Create the system restore point
	; StrCpy $restore_point_success "no"
	; DetailPrint "Start setting system restore point: ${RESTORE_POINT_NAME_UNINSTALL}"
	; SysRestore::StartUnRestorePoint /NOUNLOAD "${RESTORE_POINT_NAME_UNINSTALL}"
	; Pop $0
	; ${If} $0 != 0
	; DetailPrint "Error occured when starting setting system restore point, return value=|$0|"
	; ${Else}
	; StrCpy $restore_point_success "yes"
	; ${Endif}

	; we do not use this code any more after we call un.read_registry_service_options
/* 	${If} ${FileExists} "$INSTDIR\npf.sys"
		${If} ${FileExists} "$INSTDIR\npcap.sys"
			StrCpy $winpcap_mode "yes"
		${Else}
			StrCpy $winpcap_mode "yes2"
		${EndIf}
	${Else}
		StrCpy $winpcap_mode "no"
	${EndIf} */

	; Check windows version
	Call un.checkWindowsVersion
	DetailPrint "Windows CurrentVersion: $R0 ($os_ver)"

	; Stop the driver service before we uninstall it
	DetailPrint "Trying to stop the driver.."
	Call un.stop_driver_service
	${If} $ndis6_driver == "yes"
		terminate_back_1:
		ExecWait '"$INSTDIR\NPFInstall.exe" -n -d' $0
		${If} $0 == "0"
			; get the processes that are using Npcap
			nsExec::ExecToStack '"$INSTDIR\NPFInstall.exe" -n -check_dll'
			Pop $0
			Pop $1
			StrCpy $1 $1 -2
			${If} $1 != "<NULL>"
				DetailPrint "Failed to stop the driver. Please close programs: $1 which may be using Npcap and try again."
				${IfNot} ${Silent}
					MessageBox MB_YESNO "Failed to uninstall Npcap because it is in use by application(s): $1. You may choose the Yes button to terminate that software now, or hit No, close the software manually, and restart the Npcap uninstaller." IDYES terminate_retry_1 IDNO uninstall_fail
					terminate_retry_1:
					ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc' $0
					Goto terminate_back_1
				${Else}
					${If} $no_kill == "no"
						ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc_polite' $0
						ExecWait '"$INSTDIR\NPFInstall.exe" -n -d' $0
					${Else}
						Goto uninstall_fail
					${EndIf}
				${EndIf}
			${EndIf}
		${EndIf}
	${EndIf}

	; Remove "C:\Windows\System32\Npcap" from PATH
	; Call un.clear_env_var

	; Remove the files
	; uninstall_win7_32bit
	${If} $is_64bit == "no"
		; delete the 32-bit DLLs and EXEs in System folder
		StrCpy $cur_system_folder "System32"
		terminate_back_2:
		Call un.remove_win7_XXbit_system_dlls
		${If} $err_flag != ""
			; get the processes that are using Npcap
			nsExec::ExecToStack '"$INSTDIR\NPFInstall.exe" -n -check_dll'
			Pop $0
			Pop $1
			StrCpy $1 $1 -2
			${If} $1 != "<NULL>"
				DetailPrint "Failed to delete: $err_flag. Please close programs: $1 which may be using Npcap and try again."
				StrCpy $err_flag ""
				${IfNot} ${Silent}
					MessageBox MB_YESNO "Failed to uninstall Npcap because it is in use by application(s): $1. You may choose the Yes button to terminate that software now, or hit No, close the software manually, and restart the Npcap uninstaller." IDYES terminate_retry_2 IDNO uninstall_fail
					terminate_retry_2:
					ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc' $0
					Goto terminate_back_2
				${Else}
					${If} $no_kill == "no"
						ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc_polite' $0
						Call un.remove_win7_XXbit_system_dlls
					${Else}
						Goto uninstall_fail
					${EndIf}
				${EndIf}
			${EndIf}
		${EndIf}

			; delete the DLLs and EXEs in home folder
			Call un.remove_win7_XXbit_home_dlls
		; uninstall_win7_64bit
		${Else}
			; delete the 32-bit DLLs and EXEs in System folder
			StrCpy $cur_system_folder "SysWOW64"
			terminate_back_3:
			Call un.remove_win7_XXbit_system_dlls
			${If} $err_flag != ""
				; get the processes that are using Npcap
				nsExec::ExecToStack '"$INSTDIR\NPFInstall.exe" -n -check_dll'
				Pop $0
				Pop $1
				StrCpy $1 $1 -2
				${If} $1 != "<NULL>"
					DetailPrint "Failed to delete: $err_flag. Please close programs: $1 which may be using Npcap and try again."
					StrCpy $err_flag ""
					${IfNot} ${Silent}
						MessageBox MB_YESNO "Failed to uninstall Npcap because it is in use by application(s): $1. You may choose the Yes button to terminate that software now, or hit No, close the software manually, and restart the Npcap uninstaller." IDYES terminate_retry_3 IDNO uninstall_fail
						terminate_retry_3:
						ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc' $0
						Goto terminate_back_3
					${Else}
						${If} $no_kill == "no"
							ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc_polite' $0
							Call un.remove_win7_XXbit_system_dlls
						${Else}
							Goto uninstall_fail
						${EndIf}
					${EndIf}
				${EndIf}
			${EndIf}

			; disable Wow64FsRedirection
			System::Call kernel32::Wow64EnableWow64FsRedirection(i0)

			; delete the 64-bit DLLs and EXEs in System folder
			StrCpy $cur_system_folder "System32"
			terminate_back_4:
			Call un.remove_win7_XXbit_system_dlls
			${If} $err_flag != ""
				; get the processes that are using Npcap
				nsExec::ExecToStack '"$INSTDIR\NPFInstall.exe" -n -check_dll'
				Pop $0
				Pop $1
				StrCpy $1 $1 -2
				${If} $1 != "<NULL>"
					DetailPrint "Failed to delete: $err_flag. Please close programs: $1 which may be using Npcap and try again."
					StrCpy $err_flag ""
					${IfNot} ${Silent}
						MessageBox MB_YESNO "Failed to uninstall Npcap because it is in use by application(s): $1. You may choose the Yes button to terminate that software now, or hit No, close the software manually, and restart the Npcap uninstaller." IDYES terminate_retry_4 IDNO uninstall_fail
						terminate_retry_4:
						ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc' $0
						Goto terminate_back_4
					${Else}
						${If} $no_kill == "no"
							ExecWait '"$INSTDIR\NPFInstall.exe" -n -kill_proc_polite' $0
							Call un.remove_win7_XXbit_system_dlls
						${Else}
							Goto uninstall_fail
						${EndIf}
					${EndIf}
				${EndIf}
			${EndIf}

			; re-enable Wow64FsRedirection
			System::Call kernel32::Wow64EnableWow64FsRedirection(i1)

			; delete the DLLs and EXEs in home folder
			Call un.remove_win7_XXbit_home_dlls
		${EndIf}

	; Uninstall the driver
    Call un.registerServiceAPI_win7

	; Remove "Npcap Loopback Adapter" if it exists
  ExecWait '"$INSTDIR\NPFInstall.exe" -n -ul' $0

	; Delete our winpcap-nmap and any WinPcapInst registry keys
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst"
	DeleteRegKey HKLM "Software\Npcap"

	; We do not delete the logs, because some logs also contain uninstall infos
	; Delete $INSTDIR\install.log
	; Delete $INSTDIR\NPFInstall.log
	; Delete $INSTDIR\Packet.log

	; Delete NPFInstall.exe
	Delete $INSTDIR\NPFInstall.exe
	${If} $winpcap_mode == "yes"
		Delete $INSTDIR\NPFInstall2.exe
	${EndIf}

	; Delete the uninstaller
	Delete $INSTDIR\uninstall.exe
	
	Delete $INSTDIR\loopback.ini

	RMDir "$INSTDIR"

	; Close the system restore point
	; ${If} $restore_point_success == "yes"
		; DetailPrint "Finish setting system restore point: ${RESTORE_POINT_NAME_UNINSTALL}"
		; SysRestore::FinishRestorePoint /NOUNLOAD
		; Pop $0
		; ${If} $0 != 0
		; DetailPrint "Error occured when finishing setting system restore point, return value=|$0|"
		; ${EndIf}
	; ${EndIf}

	${If} $no_confirm == "yes"
		SetAutoClose true
	${EndIf}
	Goto uninstall_ok

uninstall_fail:
	Abort
uninstall_ok:
	${If} $install_ok == "no"
		Abort
	${EndIf}

SectionEnd
!endif
