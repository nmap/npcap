## Npcap 0.99-r5 [2018-05-01]

* Restored installer code to silently uninstall WinPcap if silent installation
  in WinPcap API-compatible mode is needed (Npcap OEM only).

* Removed several optional passthrough driver functions that can be handled
  more efficiently by NDIS, since Npcap was not using them.

* Added validation of IRP parameters for additional security.

* Fixed a crash reported via Microsoft crash telemetry,
  `DRIVER_IRQL_NOT_LESS_OR_EQUAL` in `NPF_SendCompleteExForEachOpen` when the
  system is suspended. Fixes [#1193](http://issues.nmap.org/1193).

* Fixed a crash reported via Microsoft crash telemetry,
  `DRIVER_IRQL_NOT_LESS_OR_EQUAL` in `NPF_IOControl` when setting
  `OID_GEN_CURRENT_LOOKAHEAD`. Fixes [#1194](http://issues.nmap.org/1194).

* Bundle and install the correct public code signing certificate. The
  certificate used to sign Npcap was updated for Npcap 0.99-r4, but the public
  cert file included was not, leading to some unwanted publisher trust dialogs
  during installation.

## Npcap 0.99-r4 [2018-04-19]

* On Windows 7, if Npcap driver installation fails due to maximum NDIS filters
  installed, attempt to increase the limit. No such limit exists on other
  Windows versions. Fixes [#1182](http://issues.nmap.org/1182).

* Avoid some cmd.exe popup windows during installation. See
  [#1188](http://issues.nmap.org/1188).

* Improve the license to allow unlimited copies of Npcap to be used
  (removes the 5 copy limitation) if the copies are solely used for
  Nmap and/or Wireshark.

## Npcap 0.99-r3 [2018-04-06]

* Fix recording of the Npcap Loopback Adapter's name in the service registry
  key. Loopback packet injection was broken in WinPcap API-compatible mode in
  Npcap 0.99-r1 and 0.99-r2. Fixes [#1165](http://issues.nmap.org/1165).

* Fix a double-close of a Registry key which could cause a crash in Packet.dll
  when debugging. Fixes [#1163](http://issues.nmap.org/1163).

## Npcap 0.99-r2 [2018-03-13]

* Fix installer to work on 32-bit Windows.

## Npcap 0.99-r1 [2018-03-05]

* We now offer an Npcap OEM Edition internal-use license. This
  provides all the advantages of Npcap OEM (such as the silent
  installer) and removes the 5-copy limitation of the free Npcap,
  while also providing for commercial support and updates.  It is
  for companies who only want to use Nmap internally.  We also still
  offer the Npcap OEM redistribution license for companies wanting to
  redistribute Npcap with their software.  See
  https://nmap.org/npcap/oem/.

* Improved installation of the Npcap Loopback Adapter, ensuring it can be
  correctly removed and reinstalled.

* Packet.DLL now only looks in the driver service's `Parameters` Registry key
  for installation options; in future releases, Npcap may stop writing these
  options to the `HKLM:\Software\Npcap` registry key.

* When NpcapHelper.exe is used for UAC elevation, the pipe it uses to
  communicate with the calling process is now restricted to the user SID of the
  calling process. Previously, any user could cause NpcapHelper to obtain
  handles to other devices, though the handles were only valid for the calling
  process.

* Performed Visual Studio Code Analysis on Packet.DLL and cleaned up several
  code health issues.

* Improved debug logging, error checking, and diagnostics throughout.

## Npcap 0.98 [2018-01-10]

* Fix digital signatures for some files: OEM drivers were missing the Microsoft
  Attestation signature required for Windows 10 1703, and the installer was
  missing the SHA-1 signature required for Windows Vista.

## Npcap 0.97 [2017-11-27]

* Only include data rate and channel fields in the RadioTap header if they are
  reported by the underlying WiFi card driver. See
  [#1036](http://issues.nmap.org/1036).

* When the Npcap installer detects that WinPcap is present, it will default to
  installing in WinPcap API-compatible mode, replacing WinPcap. This can be
  changed by the user in the interactive installer, or by setting the
  `/winpcap_mode=no` command-line option.

* The Silent installation feature of the Npcap installer is now limited to the
  [Npcap OEM edition](https://nmap.org/npcap/oem/).

## Npcap 0.96 [2017-10-31]

* Set the `*IfType`, `*MediaType`, and `*PhysicalMediaType` registry values for
  the Npcap Loopback Adapter. The values set should reduce the amount of
  configuration that Windows attempts to do on the adapter, preventing it from
  being labeled "Unknown Network."

* Record the ID of the Npcap Loopback Adapter in the registry when creating it,
  instead of only in the installer. This allows users to remove and create the
  adapter with NPFInstall directly, without requiring a reinstallation of Npcap.

* Expand the Npcap public license to allow 5 installations rather than only 1.

* Fix memory layout and accounting when writing Radiotap headers in raw 802.11
  monitor mode. Fixes [#1001](http://issues.nmap.org/1001),
  [#1028](http://issues.nmap.org/1028), and [#1036](http://issues.nmap.org/1036).

## Npcap 0.95 [2017-10-19]

* When upgrading, existing installation options will be retrieved from the
  Registry. Command-line installer options will still override these.

* The installer detects Win10pcap as distinct from WinPcap; since the installer
  cannot uninstall Win10pcap, WinPcap API-compatible mode will be disabled in
  the installer when it is present. Fixes [#999](http://issues.nmap.org/999).

* The npcap.cat file is no longer dual-signed; since it was not a PE
  executable, only one signature is supported. The invalid signature was
  causing some installation failures. Fixes [#994](http://issues.nmap.org/994).

* Silent installs will not downgrade the Npcap version unless the new
  `/downgrade=yes` option is given. Any version of [Npcap OEM](http://nmap.org/npcap/oem/)
   will be considered a "newer version" than any non-OEM version.

## Npcap 0.94 [2017-08-29]

* Npcap no longer prevents checksum offloading and Large Send Offloading on
  adapters that support them. This may cause problems with sniffing outgoing
  packets on those interfaces when those features are enabled, but users can
  disable them through standard Windows configuration means. Fixes
  [#989](http://issues.nmap.org/989)

## Npcap 0.93 [2017-07-27]

* Move the driver's Service Registry values from the
  `HKLM:\SYSTEM\CurrentControlSet\Services\npcap` key to the `Parameters`
  subkey. Applying Windows upgrades such as Windows 10 Creators Update deletes
  nonstandard values from the service key; the Parameters subkey is where these
  should be stored instead.

* Prevent the installer/uninstaller from crashing when faced with an incomplete
  Npcap installation, such as that created by applying a Windows version
  upgrade. Safely distinguish between old WinPcap installations and broken
  Npcap-in-WinPcap-API-mode installations. Fixes [#906](http://issues.nmap.org/906)

## Npcap 0.92 [2017-06-12]

* Force overwrite of files in installer, since uninstallers from versions
  0.78r5 through 0.81 do not remove npcap.sys, leading to mismatched driver vs
  DLL versions.

* New installer commandline option to skip setting a restore point:
  `/disable_restore_point=yes`

## Npcap 0.91 [2017-06-06]

* Fix WiFi interruption with certain hardware. This is a regression introduced
  in Npcap 0.90, which had optimistically removed the fix from 0.10-r15.

## Npcap 0.90 [2017-05-26]

* Fix BSOD introduced in 0.85; Locking while being cleaned up is bad.

* Fix WiFi interruption on Windows 7 in some circumstances, as demonstrated by
  inability to connect when Kaspersky Internet Security is installed.

## Npcap 0.86 [2017-04-12]

* Fix BSOD introduced in 0.85; wrong driver build had been packaged. Fixes [#840](http://issues.nmap.org/840)

## Npcap 0.85 [2017-04-10]

* Fix BSOD by reverting to simpler pre-0.82 data structures but retaining the
  spinlock improvement that was the core of that fix.

## Npcap 0.84 [2017-03-28]

* Fix a failure of 64-bit Npcap when installed in Admin-Only mode.
  [#814](http://issues.nmap.org/814)

## Npcap 0.83 [2017-03-04]

* Fix a crash caused by recieving loopback traffic after Windows starts to
  sleep. [#721](http://issues.nmap.org/721)

* Don't override CLI installer options like `/wpcap_mode` when WinPcap is
  found. [#717](http://issues.nmap.org/717)

* Restore the uninstaller instruction that deletes the npcap driver files.

## Npcap 0.82 [2017-02-23]

* Fix a crash that happened when many concurrent processes were using Npcap.
  If several of these quit during processing of a packet, the linked list of
  processes could become corrupted. Solved this by using a fixed array with
  copy-and-swap instead.

## Npcap 0.81 [2017-02-16]

* Moved distribution of executable installer to http://npcap.org/ from Github.

* Write log files in UTF-8 encoding to preserve localized error messages.

* Report human-readable error when LWF filter fails to be installed.

* Add `*NdisDeviceType=1` key to registry for Loopback adapter. Fixes [#653](http://issues.nmap.org/653)

## Npcap 0.80 [2017-01-09]

* Signed the uninstaller executable.

* Removed the legacy code supporting Windows XP and earlier.

* Added this CHANGELOG

* Fixed a few null pointer dereferences that may have led to Blue Screens under
  some scenarios.

* Restored changes from 0.78 r2 through 0.78 r4 that were accidentally omitted
  from 0.78 r5.

## Npcap 0.78 r5 [2016-12-15]

* Microsoft Attestation-signed drivers for Windows 10, required in Win10 1607.
  See [#492](http://issues.nmap.org/492)

* Removed Windows XP support from the executable installer. XP users can use
  WinPcap instead, as that is all that we were installing on that platform.

## Npcap 0.78 r4 [2016-12-10]

* Fixed the bug that "Npcap Loopback Adapter" can't be uninstalled.

## Npcap 0.78 r3 [2016-12-10]

* The uninstaller allows users to terminate processes that are using Npcap.

## Npcap 0.78 r2 [2016-12-03]

* The uninstaller lists the processes that are currently using Npcap,
  preventing a clean uninstall.

## Npcap 0.78 [2016-11-23]

* The uninstaller warns when it is unable to delete DLLs that are in use by
  applications.

## Npcap 0.11 [2016-11-21]

* Updated the WDK from 10.0.10586 to 10.0.14393.

## Npcap 0.10 r18 [2016-11-08]

* Improved the error message of invalid adapter name in WlanHelper.

## Npcap 0.10 r17 [2016-11-07]

* Built WlanHelper.exe in Unicode instead of Multi-Byte. This will fix the
  wrong display of non-English characters.

## Npcap 0.10 r16 [2016-11-07]

* Fixed the bug that some functions of WlanHelper.exe doesn't work.

## Npcap 0.10 r15 [2016-11-05]

* Fixed the bug that using Npcap to capture at the first time causes limited
  connectivity on Wi-Fi adapters.

## Npcap 0.10 r14 [2016-11-03]

* Fixed the bug that Npcap mode and WinPcap compatible mode can't use the
  loopback interface at the same time.

## Npcap 0.10 r13 [2016-11-01]

* Added the `/sign_mode` option for installer to choose to install SHA1-signed or
  SHA2-signed drivers.

## Npcap 0.10 r12 [2016-10-25]

* Fixed the issue that Nping shows both protocol unreachable and successful
  replies for "nping <Local IP>".

## Npcap 0.10 r11 [2016-10-24]

* Fixed the issue that Nping shows both protocol unreachable and successful
  replies for "nping 127.0.0.1".

## Npcap 0.10 r10 [2016-10-23]

* The uninstaller will not show the finish page if run with "/Q".

## Npcap 0.10 r9 [2016-10-17]

* Fixed the BSoD that happens when the OS sleeps after using Npcap Loopback
  Adapter.

## Npcap 0.10 r8 [2016-10-16]

* Improved the error messages of WlanHelper.exe.

## Npcap 0.10 r7 [2016-10-08]

* Raw 802.11 capture is provided without re-installing the driver!

## Npcap 0.10 r6 [2016-10-04]

* Fixed the BSoD that `NPF_RemoveFromGroupOpenArray()` referenced the freed group
  head.

## Npcap 0.10 r5 [2016-10-03]

* Fixed the "PAGE FAULT IN NONPAGED AREA" BSoD about the group adapter removal
  reported by Pavel.

## Npcap 0.10 r4 [2016-10-02]

* Fixed some BSoDs that causes the system to halt.

## Npcap 0.10 r3 [2016-10-02]

* Now NPFInstall debug traces will be logged into
  C:\Program Files\Npcap\NPFInstall.log

## Npcap 0.10 r2 [2016-09-21]

* Fixed the BSoD that `NPF_TapEx()` accessed the CPU buffer of the `OPEN_INSTANCE`
  that was released.

## Npcap 0.10 [2016-09-20]

* Fixed the bug that `PacketGetNetType()` doesn't return the correct `DLT_NULL`
  value on Nmap.
