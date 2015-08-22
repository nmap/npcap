;; Custom winpcap for nmap
;; Recognizes the options (case sensitive):
;;   /S              silent install
;;   /NPFSTARTUP=NO  start NPF now and at startup (only has effect with /S)

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

;; Yang Luo
;; Updated to 0.01, June 2015

;; Yang Luo
;; Updated to 0.02, July 2015

;; Yang Luo
;; Updated to 0.03, July 2015

;; Yang Luo
;; Updated to 0.04, August 2015

SetCompressor /SOLID /FINAL lzma

;--------------------------------
;Include Modern UI

  !include "MUI.nsh"
  !include "FileFunc.nsh"
  !include "EnvVarUpdate.nsh"
  !include "LogicLib.nsh"

;--------------------------------
;General

; The version of Npcap
!define VERSION "0.04"
!define WIN_VERSION "0.4.0.815"

; The name of the installer
Name "Npcap ${VERSION} for Nmap (beta)"

; The file to write
OutFile "npcap-nmap-${VERSION}.exe"

Var /GLOBAL os_ver
Var /GLOBAL admin_only
Var /GLOBAL winpcap_mode
Var /GLOBAL driver_name
Var /GLOBAL dlt_null

RequestExecutionLevel admin

; These leave either "1" or "0" in $0.
Function is64bit
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
FunctionEnd
Function un.is64bit
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
FunctionEnd

VIProductVersion "${WIN_VERSION}"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "Npcap"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "FileDescription" "Npcap ${VERSION} for Nmap installer"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright 2015 Insecure.Com LLC, Nmap Project"

;--------------------------------
; Windows API Definitions

!define SC_MANAGER_ALL_ACCESS           0x3F
!define SERVICE_ALL_ACCESS              0xF01FF

; Service Types
!define SERVICE_FILE_SYSTEM_DRIVER      0x00000002
!define SERVICE_KERNEL_DRIVER           0x00000001
!define SERVICE_WIN32_OWN_PROCESS       0x00000010
!define SERVICE_WIN32_SHARE_PROCESS     0x00000020
!define SERVICE_INTERACTIVE_PROCESS     0x00000100

; Service start options
!define SERVICE_AUTO_START              0x00000002
!define SERVICE_BOOT_START              0x00000000
!define SERVICE_DEMAND_START            0x00000003
!define SERVICE_DISABLED                0x00000004
!define SERVICE_SYSTEM_START            0x00000001

; Service Error control
!define SERVICE_ERROR_CRITICAL          0x00000003
!define SERVICE_ERROR_IGNORE            0x00000000
!define SERVICE_ERROR_NORMAL            0x00000001
!define SERVICE_ERROR_SEVERE            0x00000002

; Service Control Options
!define SERVICE_CONTROL_STOP            0x00000001
!define SERVICE_CONTROL_PAUSE           0x00000002



;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

!insertmacro MUI_PAGE_LICENSE "LICENSE"
Page custom adminOnlyOptionsPage doAdminOnlyOptions
; Don't let user choose where to install the files. WinPcap doesn't let people, and it's one less thing for us to worry about.
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
Page custom optionsPage doOptions
Page custom finalPage doFinal

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Reserves

ReserveFile "options_admin_only.ini"
ReserveFile "options.ini"
ReserveFile "final.ini"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

;--------------------------------

!insertmacro GetParameters
!insertmacro GetOptions

; This function is called on startup. IfSilent checks
; if the flag /S was specified. If so, it sets the installer
; to run in "silent mode" which displays no windows and accepts
; all defaults.

; We also check if there is a previously installed winpcap
; on this system. If it's the same as the version we're installing,
; abort the install. If not, prompt the user about whether to
; replace it or not.

Function .onInit
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "options_admin_only.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "options.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "final.ini"

  var /GLOBAL inst_ver
  var /GLOBAL my_ver
  var /GLOBAL npf_startup
  StrCpy $my_ver "${VERSION}"
  StrCpy $npf_startup "YES"

  ; Always use the requested /D= $INSTDIR if given.
  StrCmp $INSTDIR "" "" instdir_nochange
  ; On 64-bit Windows, $PROGRAMFILES is "C:\Program Files (x86)" and
  ; $PROGRAMFILES64 is "C:\Program Files". We want "C:\Program Files"
  ; on 32-bit or 64-bit.
  StrCpy $INSTDIR "$PROGRAMFILES\Npcap"
  Call is64bit
  StrCmp $0 "0" instdir_nochange
  StrCpy $INSTDIR "$PROGRAMFILES64\Npcap"
  instdir_nochange:

  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/NPFSTARTUP=" $npf_startup

  IfSilent do_silent no_silent

  do_silent:
    SetSilent silent
    IfFileExists "$INSTDIR\NPFInstall.exe" silent_checks
    return
    silent_checks:
      ; check for the presence of Nmap's custom WinPcapInst registry key:
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "InstalledBy"
      StrCmp $0 "Nmap" silent_uninstall winpcap_installedby_keys_not_present

      winpcap_installedby_keys_not_present:
      ; check for the presence of WinPcapInst's UninstallString
      ; and manually cleanup registry entries to avoid running
      ; the GUI uninstaller and assume our installer will overwrite
      ; the files. Needs to be checked in case someone (force)
      ; installs WinPcap over the top of our installation
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"
      StrCmp $0 "" winpcap_keys_not_present

      DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst"

      ReadRegStr $0 "HKLM" "Software\Npcap" ""
      StrCmp $0 "" winpcap_keys_not_present

      Delete $0\rpcapd.exe
      Delete $0\LICENSE
      Delete $0\uninstall.exe
      ; Official 4.1 installer creates an install.log
      Delete $0\install.log
      RMDir "$0"
      DeleteRegKey HKLM "Software\Npcap"

      ; because we've deleted their uninstaller, skip the next
      ; registry key check (we'll still need to overwrite stuff)
      Goto winpcap-nmap_keys_not_present

      winpcap_keys_not_present:

      ; if our old registry key is present then assume all is well
      ; (we got this far so the official WinPcap wasn't installed)
      ; and use our uninstaller to (magically) silently uninstall
      ; everything cleanly and avoid having to overwrite files
      ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap" "UninstallString"
      StrCmp $0 "" winpcap-nmap_keys_not_present silent_uninstall

      winpcap-nmap_keys_not_present:

      ; setoverwrite on to try and avoid any problems when trying to install the files
      ; wpcap.dll is still present at this point, but unclear where it came from
      SetOverwrite on

      ; try to ensure that npf has been stopped before we install/overwrite files
      ExecWait '"net stop $driver_name"'

      return

      silent_uninstall:
        ; Our InstalledBy string is present, UninstallString should have quotes and uninstall.exe location
        ; and this file should support a silent uninstall by passing /S to it.
        ; we could read QuietUninstallString, but this should be exactly the same as UninstallString with /S on the end.
        ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"
        ExecWait '$0 /S _?=$INSTDIR'
      return

  no_silent:
    IfFileExists "$INSTDIR\NPFInstall.exe" do_version_check
    return

  do_version_check:

    GetDllVersion "$INSTDIR\NPFInstall.exe" $R0 $R1
    IntOp $R2 $R0 / 0x00010000
    IntOp $R3 $R0 & 0x0000FFFF
    IntOp $R4 $R1 / 0x00010000
    IntOp $R5 $R1 & 0x0000FFFF
    StrCpy $inst_ver "$R2.$R3.$R4.$R5"

    StrCmp $inst_ver $my_ver same_ver

    MessageBox MB_YESNO|MB_ICONQUESTION "Npcap version $inst_ver exists on this system. Replace with version $my_ver?" IDYES try_uninstallers
    quit

  same_ver:
    MessageBox MB_YESNO|MB_ICONQUESTION "Npcap version $inst_ver already exists on this system. Reinstall this version?" IDYES try_uninstallers
    quit

  try_uninstallers:

    ; check for UninstallString and use that in preference (should already have double quotes and uninstall.exe)
    ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"
    StrCmp $0 "" no_uninstallstring
    IfFileExists "$0" uninstaller_exists no_uninstallstring
    uninstaller_exists:
    ExecWait '$0 _?=$INSTDIR'
    return

    no_uninstallstring:
    ; didn't find an UninstallString, check for our old UninstallString and if uninstall.exe exists:
    ReadRegStr $0 "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap" "UninstallString"
    StrCmp $0 "" still_no_uninstallstring
    IfFileExists "$0" old_uninstaller_exists still_no_uninstallstring
    old_uninstaller_exists:
    MessageBox MB_OK "Using our old UninstallString, file exists"
    ExecWait '$0 _?=$INSTDIR'
    return

    still_no_uninstallstring:
    ; still didn't find anything, try looking for an uninstall.exe file at:
      ReadRegStr $0 "HKLM" "Software\Npcap" ""
    ; Strip any surrounding double quotes from around the install string,
    ; as WinPcap hasn't used quotes in the past, but our old installers did.
    ; Check the first and last character for safety!
    StrCpy $1 $0 1
    StrCmp $1 "$\"" maybestripquotes nostrip
    maybestripquotes:
    StrLen $1 $0
    IntOp $1 $1 - 1
    StrCpy $1 $0 1 $1
    StrCmp $1 "$\"" stripquotes nostrip
    stripquotes:
    StrCpy $0 $0 -1 1
    nostrip:
    IfFileExists "$0\uninstall.exe" run_last_uninstaller no_uninstall_exe
    run_last_uninstaller:
    ExecWait '"$0\Uninstall.exe" _?=$INSTDIR'
    no_uninstall_exe:
    ; give up now, we've tried our hardest to determine a valid uninstaller!
    return

FunctionEnd

Function adminOnlyOptionsPage
  IfFileExists "$SYSDIR\wpcap.dll" winpcap_exist no_winpcap_exist
  winpcap_exist:
    WriteINIStr "$PLUGINSDIR\options_admin_only.ini" "Field 4" "Text" "Npcap detected you have installed WinPcap, in order to Install Npcap \r\nin WinPcap API-compatible Mode, you must uninstall WinPcap first."
    WriteINIStr "$PLUGINSDIR\options_admin_only.ini" "Field 3" "State" 0
    WriteINIStr "$PLUGINSDIR\options_admin_only.ini" "Field 3" "Flags" "DISABLED"
  no_winpcap_exist:
  !insertmacro MUI_HEADER_TEXT "Security and API Options" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "options_admin_only.ini"
FunctionEnd

Function doAdminOnlyOptions
  ReadINIStr $0 "$PLUGINSDIR\options_admin_only.ini" "Field 1" "State"
  ${If} $0 == "0"
    StrCpy $admin_only "no"
  ${Else}
    StrCpy $admin_only "yes"
  ${EndIf}

  ReadINIStr $0 "$PLUGINSDIR\options_admin_only.ini" "Field 2" "State"
  ${If} $0 == "0"
    StrCpy $dlt_null "no"
  ${Else}
    StrCpy $dlt_null "yes"
  ${EndIf}

  ReadINIStr $0 "$PLUGINSDIR\options_admin_only.ini" "Field 3" "State"
  ${If} $0 == "0"
    StrCpy $winpcap_mode "no"
    StrCpy $driver_name "npcap"
  ${Else}
    StrCpy $winpcap_mode "yes"
    StrCpy $driver_name "npf"
  ${EndIf}
FunctionEnd

Function optionsPage
  !insertmacro MUI_HEADER_TEXT "Driver Options" ""
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "options.ini"
FunctionEnd

Function doOptions
  ReadINIStr $0 "$PLUGINSDIR\options.ini" "Field 1" "State"
  StrCmp $0 "0" do_options_start do_options_end
  do_options_start:
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "Start" 3
  do_options_end:
FunctionEnd

Function finalPage
  ; diplay a page saying everything's finished
  !insertmacro MUI_HEADER_TEXT "Finished" "Thank you for installing Npcap"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "final.ini"
FunctionEnd

Function doFinal
 ; don't need to do anything
FunctionEnd

Function registerServiceAPI_xp_vista
  ; delete the npf service to avoid an error message later if it already exists
  System::Call 'advapi32::OpenSCManagerA(,,i ${SC_MANAGER_ALL_ACCESS})i.r0'
  System::Call 'advapi32::OpenServiceA(i r0,t "npf", i ${SERVICE_ALL_ACCESS}) i.r1'
  System::Call 'advapi32::DeleteService(i r1) i.r6'
  System::Call 'advapi32::CloseServiceHandle(i r1) n'
  System::Call 'advapi32::CloseServiceHandle(i r0) n'
  ; create the new npf service
  System::Call 'advapi32::OpenSCManagerA(,,i ${SC_MANAGER_ALL_ACCESS})i.R0'
  System::Call 'advapi32::CreateServiceA(i R0,t "npf",t "NetGroup Packet Filter Driver",i ${SERVICE_ALL_ACCESS},i ${SERVICE_KERNEL_DRIVER}, i ${SERVICE_DEMAND_START},i ${SERVICE_ERROR_NORMAL}, t "system32\drivers\npf.sys",,,,,) i.r1'
  StrCmp $1 "0" register_xp_vista_fail register_xp_vista_success
  register_xp_vista_fail:
    DetailPrint "Failed to create the npf service for XP and Vista"
    IfSilent close_register_xp_vista_handle register_xp_vista_fail_messagebox
    register_xp_vista_fail_messagebox:
      MessageBox MB_OK "Failed to create the npf service for XP and Vista. Please try installing Npcap again, or use the official Npcap installer from www.nmap.org"
    Goto close_register_xp_vista_handle
  register_xp_vista_success:
    DetailPrint "The npf service for XP and Vista was successfully created"
  close_register_xp_vista_handle:
  System::Call 'advapi32::CloseServiceHandle(i R0) n'
FunctionEnd

Function un.registerServiceAPI_xp_vista
  System::Call 'advapi32::OpenSCManagerA(,,i ${SC_MANAGER_ALL_ACCESS})i.r0'
  System::Call 'advapi32::OpenServiceA(i r0,t "npf", i ${SERVICE_ALL_ACCESS}) i.r1'
  System::Call 'advapi32::DeleteService(i r1) i.r6'
  StrCmp $6 "0" unregister_xp_vista_fail unregister_xp_vista_success
  unregister_xp_vista_fail:
    DetailPrint "Failed to delete the npf service for XP and Vista"
    Goto close_unregister_xp_vista_handle
  unregister_xp_vista_success:
    DetailPrint "The npf service for XP and Vista was successfully deleted"
  close_unregister_xp_vista_handle:
  System::Call 'advapi32::CloseServiceHandle(i r1) n'
  System::Call 'advapi32::CloseServiceHandle(i r0) n'
FunctionEnd

Function registerServiceAPI_win7
  ; delete the npf service to avoid an error message later if it already exists
  ; create the Npcap Loopback Adapter, used for capturing loopback packets
  ExecWait '"$INSTDIR\NPFInstall.exe" -il'
  ; install the WFP callout driver
  ExecWait '"$INSTDIR\NPFInstall.exe" -iw' $0
  ; install the NDIS filter driver
  ExecWait '"$INSTDIR\NPFInstall.exe" -i' $0
  StrCmp $0 "0" register_win7_success register_win7_fail

  register_win7_fail:
    DetailPrint "Failed to create the npf service for Win7 and Win8"
    IfSilent register_win7_done register_win7_fail_messagebox
    register_win7_fail_messagebox:
      MessageBox MB_OK "Failed to create the npcap service for Win7 and Win8. Please try installing Npcap again, or use the official Npcap installer from www.nmap.org"
    Goto register_win7_done
  register_win7_success:
    DetailPrint "The npf service for Win7 and Win8 was successfully created"
  register_win7_done:
FunctionEnd

Function un.registerServiceAPI_win7
  ;ExecWait '"$INSTDIR\NPFInstall.exe" -u' $0
  ExecWait '"$INSTDIR\NPFInstall.exe" -uw' $0
  ExecWait '"$INSTDIR\NPFInstall.exe" -ul' $0
  StrCmp $0 "0" unregister_win7_success unregister_win7_fail
  
  unregister_win7_fail:
    DetailPrint "Failed to delete the npf service for Win7 and Win8"
    Goto unregister_win7_done
  unregister_win7_success:
    DetailPrint "The npf service for Win7 and Win8 was successfully deleted"
  unregister_win7_done:
FunctionEnd

Function autoStartWinPcap
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "Start" 1
    nsExec::Exec "net start $driver_name"
FunctionEnd


;--------------------------------
; The stuff to install
Section "WinPcap" SecWinPcap

  ; stop the service, in case it's still registered, so files can be
  ; safely overwritten and the service can be deleted.
  nsExec::Exec "net stop $driver_name"

  ; NB: We may need to introduce a check here to ensure that NPF
  ; has been stopped before we continue, otherwise we Sleep for a
  ; while and try the check again. This might help prevent any race
  ; conditions during a silent install (and potentially during the
  ; slower GUI installation.

  ; These x86 files are automatically redirected to the right place on x64
  ${If} $winpcap_mode == "yes"
    SetOutPath $SYSDIR
  ${Else}
    SetOutPath $SYSDIR\Npcap
  ${EndIf}
  File pthreadVC.dll
  File wpcap.dll
  File win7_above\x86\NPcapHelper.exe

  ; Check windows version
  ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  DetailPrint "Windows CurrentVersion: $R0"
  StrCmp $R0 '6.0' vista_files
  StrCpy $R0 $R0 2
  StrCmp $R0 '6.' win7_files

  ; xp_files:
  StrCpy $os_ver 'xp' 5
  File nt5\x86\Packet.dll
  Goto install_xp_vista

  vista_files:
    StrCpy $os_ver 'vista' 5
    File vista\x86\Packet.dll
    Goto install_xp_vista

  win7_files:
    StrCpy $os_ver 'win7' 5
	${If} $winpcap_mode == "yes"
	  File win7_above_winpcap\x86\Packet.dll
	${Else}
	  File win7_above\x86\Packet.dll
	${EndIf}
    Goto install_win7

  install_xp_vista:
    Call is64bit
    StrCmp $0 "0" install_xp_vista_32bit install_xp_vista_64bit
    
  install_win7:
    Call is64bit
    StrCmp $0 "0" install_win7_32bit install_win7_64bit

    ; Note, NSIS states: "You should always quote the path to make sure spaces
    ; in the path will not disrupt Windows to find the uninstaller."
    ; See: http://nsis.sourceforge.net/Add_uninstall_information_to_Add/Remove_Programs
    ; This matches (most) Windows installations. Rather inconsistently,
    ; DisplayIcon doesn't usually have quotes (even on Microsoft installations) and
    ; HKLM Software\PackageName doesn't usually have quotes either.

    install_xp_vista_32bit:
      SetOutPath $INSTDIR
      File rpcapd.exe
      File LICENSE
      WriteUninstaller "$INSTDIR\uninstall.exe"
      DetailPrint "Installing NDIS5.0 x86 driver for XP and Vista"
      SetOutPath $SYSDIR\drivers
      File npf.sys ; x86 NT5/NT6.0 version
      WriteRegStr HKLM "Software\Npcap" "" "$INSTDIR"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"
      Goto npfdone

    install_win7_32bit:
      SetOutPath $INSTDIR
      File rpcapd.exe
      File LICENSE
	  ${If} $winpcap_mode == "yes"
	    File win7_above_winpcap\x86\NPFInstall.exe
	  ${Else}
	    File win7_above\x86\NPFInstall.exe
	  ${EndIf}

      ${If} $winpcap_mode == "yes"
        File win7_above_winpcap\x86\npf.sys ; x86 NT6.1/NT6.2/NT6.3 version
        File win7_above_winpcap\x86\npf.inf
        File win7_above_winpcap\x86\npf_wfp.inf
        File win7_above_winpcap\x86\npf.cat
      ${Else}
        File win7_above\x86\npcap.sys ; x86 NT6.1/NT6.2/NT6.3 version
        File win7_above\x86\npcap.inf
        File win7_above\x86\npcap_wfp.inf
        File win7_above\x86\npcap.cat
      ${EndIf}

      WriteUninstaller "$INSTDIR\uninstall.exe"
      DetailPrint "Installing NDIS6.x x86 driver for Win7 and Win8"
      SetOutPath $SYSDIR\drivers
      WriteRegStr HKLM "Software\Npcap" "" "$INSTDIR"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"
      Goto npfdone

    install_xp_vista_64bit:
      SetOutPath $INSTDIR
      File rpcapd.exe
      File LICENSE
      WriteUninstaller "$INSTDIR\uninstall.exe"
      DetailPrint "Installing NDIS5.x x64 driver for XP and Vista"
      SetOutPath $SYSDIR\drivers
      ; disable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i0)
      File x64\npf.sys ; x64 NT5/NT6.0 version
      ; The x86 versions of wpcap.dll and packet.dll are
      ; installed into the right place further above.
      ; install the 64-bit version of wpcap.dll into System32
	  ${If} $winpcap_mode == "yes"
	    SetOutPath $SYSDIR
	  ${Else}
        SetOutPath $SYSDIR\Npcap
	  ${EndIf}
      File x64\wpcap.dll ; x64 NT5/NT6.0 version
      ; install the 64-bit version of packet.dll into System32
      ; check for vista, otherwise install the NT5 version (for XP and 2003)
      StrCpy $R0 $R0 2
      StrCmp $R0 '6.' vista_x64_packet
      File nt5\x64\Packet.dll ; x64 XP/2003 version
      Goto nt5_x64_packet_done
      vista_x64_packet:
      File vista\x64\Packet.dll ; x64 Vista version
      nt5_x64_packet_done:
      WriteRegStr HKLM "Software\Npcap" "" "$INSTDIR"
      ; re-enable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"
      Goto npfdone
      
    install_win7_64bit:
      SetOutPath $INSTDIR
      File rpcapd.exe
      File LICENSE
	  ${If} $winpcap_mode == "yes"
	    File win7_above_winpcap\x64\NPFInstall.exe
	  ${Else}
        File win7_above\x64\NPFInstall.exe
	  ${EndIf}

      ${If} $winpcap_mode == "yes"
        File win7_above_winpcap\x64\npf.sys ; x64 NT6.1 and above version
        File win7_above_winpcap\x64\npf.inf
        File win7_above_winpcap\x64\npf_wfp.inf
        File win7_above_winpcap\x64\npf.cat
      ${Else}
        File win7_above\x64\npcap.sys ; x64 NT6.1 and above version
        File win7_above\x64\npcap.inf
        File win7_above\x64\npcap_wfp.inf
        File win7_above\x64\npcap.cat
      ${EndIf}

      WriteUninstaller "$INSTDIR\uninstall.exe"
      DetailPrint "Installing NDIS6.x x64 driver for Win7 and Win8"
      SetOutPath $SYSDIR\drivers
      ; disable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i0)
      ; The x86 versions of wpcap.dll and packet.dll are
      ; installed into the right place further above.
      ; install the 64-bit version of wpcap.dll into System32
	  ${If} $winpcap_mode == "yes"
	    SetOutPath $SYSDIR
	  ${Else}
        SetOutPath $SYSDIR\Npcap
	  ${EndIf}
      File win7_above\x64\NPcapHelper.exe
      File x64\wpcap.dll ; x64 NT5/NT6 version
      ; install the 64-bit version of packet.dll into System32
      ; install the NT6.1 above version (for Win7 and Win8)
	  ${If} $winpcap_mode == "yes"
	    File win7_above_winpcap\x64\Packet.dll ; x64 NT6.1 and above version
	  ${Else}
        File win7_above\x64\Packet.dll ; x64 NT6.1 and above version
	  ${EndIf}
      WriteRegStr HKLM "Software\Npcap" "" "$INSTDIR"
      ; Packet.dll will read this option
      ${If} $admin_only == "yes"
        WriteRegDWORD HKLM "Software\Npcap" "AdminOnly" 1 ; make "AdminOnly" = 1 only when "admin only" is chosen
      ${Else}
        WriteRegDWORD HKLM "Software\Npcap" "AdminOnly" 0 ;
      ${EndIf}
      ; Wireshark will read this option
      ${If} $winpcap_mode == "yes"
        WriteRegDWORD HKLM "Software\Npcap" "WinPcapCompatible" 1 ; make "WinPcapCompatible" = 1 only when "WinPcap API-compatible Mode" is chosen
      ${Else}
        WriteRegDWORD HKLM "Software\Npcap" "WinPcapCompatible" 0 ;
      ${EndIf}
      ; re-enable Wow64FsRedirection
      System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
      WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayIcon" "$INSTDIR\uninstall.exe"

    npfdone:

    ; register the driver as a system service using Windows API calls
    ; this will work on Windows 2000 (that lacks sc.exe) and higher
    StrCmp $os_ver 'win7' register_service_win7
    ;registerService_xp_vista:
    Call registerServiceAPI_xp_vista
    Goto registerdone
    
    register_service_win7:
      Call registerServiceAPI_win7
    
    registerdone:

	${If} $winpcap_mode == "no"
      ; Add "system32\Npcap" directory to PATH
      DetailPrint "Adding DLL folder: $\"$SYSDIR\Npcap$\" to PATH environment variable"
      ; SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment"
      ${EnvVarUpdate} $0 "PATH" "A" "HKLM" "$SYSDIR\Npcap"
	${EndIf}

    ; Create the default NPF startup setting of 1 (SERVICE_SYSTEM_START)
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "Start" 1

    ; Npcap driver will read this option
    ${If} $admin_only == "yes"
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "AdminOnly" 1 ; make "AdminOnly" = 1 only when "admin only" is chosen
    ${Else}
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "AdminOnly" 0
    ${Endif}

    ; Npcap driver will read this option
    ${If} $dlt_null == "yes"
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "DltNull" 1 ; make "DltNull" = 1 only when "dlt null" is chosen
    ${Else}
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "DltNull" 0
    ${Endif}

    ; Copy the "Loopback" option from software key to services key
    ReadRegStr $0 HKLM "Software\Npcap" "Loopback"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\$driver_name" "Loopback" $0

    nsExec::Exec "net start $driver_name"
    nsExec::Exec "net stop $driver_name"
    nsExec::Exec "net start $driver_name"

    ; automatically start the service if performing a silent install, unless
    ; /NPFSTARTUP=NO was given.
    IfSilent 0 skip_auto_start
    StrCmp $npf_startup "NO" skip_auto_start
      Call autoStartWinPcap
    skip_auto_start:

    ; Write the rest of the uninstall keys for Windows

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayName" "Npcap ${VERSION} for Nmap"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "Publisher" "Nmap Project"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "URLInfoAbout" "http://www.nmap.org"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "URLUpdateInfo" "http://www.nmap.org"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "VersionMajor" "0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "VersionMinor" "1"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "InstalledBy" "Nmap"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "NoRepair" 1

  ; delete our legacy winpcap-nmap keys if they still exist (e.g. official 4.0.2 force installed over our 4.0.2):
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap"

SectionEnd ; end the section


;--------------------------------
;Uninstaller Section

Section "Uninstall"

  StrCpy $winpcap_mode "yes"
  StrCpy $driver_name "npf"
  IfFileExists "$INSTDIR\npf.sys" npcap_sys_checked
  StrCpy $winpcap_mode "no"
  StrCpy $driver_name "npcap"
  npcap_sys_checked:

  ; stop npf before we delete the service from the registry
  DetailPrint "Trying to stop the npf service.."
  nsExec::Exec "net stop $driver_name"
  
  ExecWait '"$INSTDIR\NPFInstall.exe" -d' $0
  ${If} $0 == "0"
    MessageBox MB_OK "Failed to stop the npf service, stop uninstallation now. Please stop using Npcap first"
    DetailPrint "Failed to stop the npf service, stop uninstallation now"
    Goto uninstall_fail
  ${EndIf}

  ${If} $winpcap_mode == "no"
    ; Remove "system32\Npcap" directory in PATH
    DetailPrint "Removing DLL folder: $\"$SYSDIR\Npcap$\" from PATH environment variable"
    ${un.EnvVarUpdate} $0 "PATH" "R" "HKLM" "$SYSDIR\Npcap"
  ${EndIf}

  ; Check windows version
  ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  DetailPrint "Windows CurrentVersion: $R0"
  StrCmp $R0 '6.0' un_vista_files
  StrCpy $R0 $R0 2
  StrCmp $R0 '6.' un_win7_files

  ; un_xp_files:
  StrCpy $os_ver 'xp' 5
  Goto check_windows_done

  un_vista_files:
    StrCpy $os_ver 'vista' 5
    Goto check_windows_done

  un_win7_files:
    StrCpy $os_ver 'win7' 5
    Goto check_windows_done
    
  check_windows_done:
    
  ; unregister the driver as a system service using Windows API calls, so it works on Windows 2000
  StrCmp $os_ver 'win7' unregister_service_win7
  
  ;unregisterService_xp_vista:
  Call un.registerServiceAPI_xp_vista
  Goto unregisterdone
  
  unregister_service_win7:
  Call un.registerServiceAPI_win7
  
  unregisterdone:

  ; delete our winpcap-nmap and any WinPcapInst registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\npcap-nmap"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst"
  DeleteRegKey HKLM "Software\Npcap"

  Delete $INSTDIR\rpcapd.exe
  Delete $INSTDIR\LICENSE
  Delete $INSTDIR\NPFInstall.exe
  Delete $INSTDIR\loopback.ini
  ${If} $winpcap_mode == "yes"
    Delete $INSTDIR\npf.sys
    Delete $INSTDIR\npf.inf
	Delete $INSTDIR\npf_wfp.inf
    Delete $INSTDIR\npf.cat
  ${Else}
    Delete $INSTDIR\npcap.sys
    Delete $INSTDIR\npcap.inf
	Delete $INSTDIR\npcap_wfp.inf
    Delete $INSTDIR\npcap.cat
  ${EndIf}
  Delete $INSTDIR\uninstall.exe

  ; This deletes the x86 files from SysWOW64 if we're on x64.
  ${If} $winpcap_mode == "yes"
    Delete $SYSDIR\Packet.dll
    Delete $SYSDIR\pthreadVC.dll
    Delete $SYSDIR\wpcap.dll
    Delete $SYSDIR\NPcapHelper.exe
  ${Else}
    Delete $SYSDIR\Npcap\Packet.dll
    Delete $SYSDIR\Npcap\pthreadVC.dll
    Delete $SYSDIR\Npcap\wpcap.dll
    Delete $SYSDIR\Npcap\NPcapHelper.exe
    RMDir "$SYSDIR\Npcap"
  ${EndIf}

  ; check for x64, delete npf.sys file from system32\drivers
  Call un.is64bit
  StrCmp $0 "0" del32bitnpf del64bitnpf
  
  del64bitnpf:
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
    DetailPrint "Windows CurrentVersion: $R0"
    StrCmp $R0 '6.0'   del64bitnpf_xp_vista
    StrCpy $R0 $R0 2
    StrCmp $R0 '6.' del64bitnpf_win7 del64bitnpf_xp_vista
  
  del32bitnpf:
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
    DetailPrint "Windows CurrentVersion: $R0"
    StrCmp $R0 '6.0'   del32bitnpf_xp_vista
    StrCpy $R0 $R0 2
    StrCmp $R0 '6.' del32bitnpf_win7 del32bitnpf_xp_vista
  
  del64bitnpf_xp_vista:
    ; disable Wow64FsRedirection
    System::Call kernel32::Wow64EnableWow64FsRedirection(i0)

    Delete $SYSDIR\drivers\npf.sys
    ; Also delete the x64 files in System32
    Delete $SYSDIR\Npcap\wpcap.dll
    Delete $SYSDIR\Npcap\Packet.dll
    RMDir "$SYSDIR\Npcap"

    ; re-enable Wow64FsRedirection
    System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
    Goto npfdeleted
  
  
  del32bitnpf_xp_vista:
    Delete $SYSDIR\drivers\npf.sys
    Goto npfdeleted
  
  
  del64bitnpf_win7:
    ; disable Wow64FsRedirection
    System::Call kernel32::Wow64EnableWow64FsRedirection(i0)

	${If} $winpcap_mode == "yes"
	  Delete $SYSDIR\drivers\npf.sys
      ; Also delete the x64 files in System32
      Delete $SYSDIR\wpcap.dll
      Delete $SYSDIR\Packet.dll
	  Delete $SYSDIR\NPcapHelper.exe
	${Else}
      Delete $SYSDIR\drivers\npcap.sys
      ; Also delete the x64 files in System32
      Delete $SYSDIR\Npcap\wpcap.dll
      Delete $SYSDIR\Npcap\Packet.dll
	  Delete $SYSDIR\Npcap\NPcapHelper.exe
      RMDir "$SYSDIR\Npcap"
	${EndIf}
    
    ; re-enable Wow64FsRedirection
    System::Call kernel32::Wow64EnableWow64FsRedirection(i1)
    Goto npfdeleted


  del32bitnpf_win7:
    ${If} $winpcap_mode == "yes"
	  Delete $SYSDIR\drivers\npf.sys
	${Else}
      Delete $SYSDIR\drivers\npcap.sys
	${EndIf}
    Goto npfdeleted


  npfdeleted:
    RMDir "$INSTDIR"
	
  uninstall_fail:

SectionEnd
