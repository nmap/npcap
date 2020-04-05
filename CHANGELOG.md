
## Npcap 0.9990 [2020-04-04]

* Improve compatibility with WinPcap's behavior regarding injected traffic.
  WinPcap uses inefficient loopback to capture all outbound traffic, but allows
  `PacketSetLoopbackBehavior()` to avoid this for injected traffic. Because of
  Npcap's more efficient design, injected traffic was never looped back up to
  protocol drivers, causing problems for some users who relied on this behavior.
  Now, injected traffic follows the same path as with WinPcap, though ordinary
  traffic is unaffected. For highest efficiency without loopback, use
  `PacketSetLoopbackBehavior(PACKET_DISABLE_LOOPBACK)`. Fixes [#1343](https://issues.nmap.org/1343),
  [#1929](https://issues.nmap.org/1929), and [GNS3/gns3-gui#2936](https://github.com/GNS3/gns3-gui/issues/2936)

* No longer honor `NDIS_PACKET_TYPE_ALL_LOCAL` set via `PacketSetHwFilter()`.
  This packet filter causes all local traffic to be routed through an unoptimized
  loopback path within NDIS, which was necessary to capture outgoing traffic in
  WinPcap but is no longer needed in Npcap. Instead, this value will be treated as
  `NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST | NDIS_PACKET_TYPE_BROADCAST`.

* Fix a bug that caused `TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE` to fall back to
  `TIMESTAMPMODE_QUERYSYSTEMTIME` even when `KeQuerySystemTimePrecise()` was
  available. Fix by Mauro Levra in [PR#23](https://github.com/nmap/npcap/pull/24).

* Installer will now install an intermediate CA cert that was missing from some
  systems, which is needed to verify the driver's digital signature. Only
  affects Windows versions prior to Windows 10.

* Backport a fix from libpcap needed to properly support
  `NdisMediumWirelessWan`. See [#1573](https://issues.nmap.org/1573).

* Include experimental support for AirPcap cards if `airpcap.dll` (not
  included) is installed.

## Npcap 0.9989 [2020-03-19]

* Fix a BSOD crash in `NPF_OpenAdapter` due to reading past the end of a
  string. Fixes [#1924](https://issues.nmap.org/1924)

* Fix a BSOD crash (NULL pointer dereference) in `NPF_Restart`.
  Fixes [#1964](https://issues.nmap.org/1964).

* Fix a memory leak in the Loopback WFP filter. Additionally, WFP callbacks
  will be unregistered when all loopback captures are closed, reducing impact
  of related code when not in use. Fixes [#1966](https://issues.nmap.org/1966).

* New Packet.DLL function `PacketSetTimestampMode()` allows a user program to
  set the method used to timestamp packets as they arrive. See [#1775](https://issues.nmap.org/1775).
  Supported modes are:
  * `TIMESTAMPMODE_SINGLE_SYNCHRONIZATION` - default monotonic timestamps based
   on `KeQueryPerformanceCounter()`
  * `TIMESTAMPMODE_QUERYSYSTEMTIME` - low-precision wall clock time based on
   `KeQuerySystemTime()`
  * `TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE` - high-precision wall clock time
   based on `KeQuerySystemTimePrecise()`, new in this release and only
   available on Windows 8 and newer. See [#1407](https://issues.nmap.org/1407).

* Remove some problematic timestamp modes:
  `TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP` and
  `TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP` were undocumented;
  `TIMESTAMPMODE_RDTSC` was x86-only and not suitable for multi-processor
  systems. See [#1829](https://issues.nmap.org/1829).

* The Npcap SDK 1.05 will be released to include the new
  `PacketSetTimestampMode()` function.

## Npcap 0.9988 [2020-03-05]

* If a capture is in progress when the system is suspended, it will continue
  without interruption after the system is woken. This also prevents capture
  interruptions when the OS makes certain network stack changes.
  Fixes [#1903](http://issues.nmap.org/1903).

* If the npcap driver is stopped, Packet.dll will attempt to start it
  automatically. This feature requires Administrator privilege and had been
  removed in Npcap 0.9983. Fixes [#1911](http://issues.nmap.org/1911). 

* Fix the check for fragmented packets in loopback capture.
  Closes [PR #22](https://github.com/nmap/npcap/pull/22).

* Eliminate clone/block/inject pattern from loopback capture except for packets
  already injected by Npcap. Should fix [#1529](http://issues.nmap.org/1529)
  and [#1789](http://issues.nmap.org/1789).

* Fix an issue in the Npcap OEM installer where silent mode would not detect a
  failure to install the npcap driver. Fixes [#1910](http://issues.nmap.org/1910).

* Improve the installer to avoid broken installations and allow the installer
  to continue if a broken installation is detected. Fixes [#1935](http://issues.nmap.org/1935).

* Formally removed support for Windows Vista and Server 2008 r1, which
  are no longer supported by Microsoft either. This allows us to support
  newer Windows WFP and NDIS features for better performance and
  compatibility. Folks who must still run these ancient Windows releases
  should use Npcap version 0.9984 from
  https://nmap.org/npcap/dist/?C=M;O=D. That was the last Npcap release
  to support the old (and less secure) SHA-128 driver signatures
  required by these Windows Vista/2008. Please note that Windows Server
  2008 r2 and Windows 7 are still supported in this release even though
  they have also passed their Microsoft end-of-life dates.

## Npcap 0.9987 [2020-02-03]

* Fix an issue where Npcap begins dropping large packets, then smaller ones
  until finally all packets are dropped. Our fix changes the way remaining free
  space in the kernel buffer is calculated, which ought to prevent the free
  space accounting from drifting from reality. Fixes
  [#1891](http://issues.nmap.org/1891).

* Fix a potential race condition when opening the loopback capture adapter. If
  two threads simultaneously determine that the WFP filters need to be
  registered, each may open a handle to the WFP engine using the same global
  pointer, leading to a double-free when the second one tries to close the
  handle.

* Allow Packet.dll and the npcap driver to skip loopback-related operations,
  including WFP and WSK setup, if the `LoopbackSupport` Registry key is set
  to 0. This configuration will not be supported by the installer, but may
  serve as a workaround for problems that may be related to Npcap's loopback
  traffic capture and injection capability.

* Ensure open handles to the Service Control Manager are closed on error in
  PacketGetFileVersion. Fixes [#1882](http://issues.nmap.org/1882).

## Npcap 0.9986 [2019-12-17]

* Fix a driver signing issue that made Npcap 0.9985 uninstallable on default
  configurations of Windows 8.1 and older, as well as certain older Windows
  Server releases. Fixes [#1856](http://issues.nmap.org/1856).

## Npcap 0.9985 [2019-12-13]

* The Nmap Project's (Insecure.Com LLC) code signing certificate has been
  renewed, and no longer exists as a SHA-1 certificate. Windows Vista and
  Server 2008 may therefore not recognize the digital signatures on the
  filter driver so a warning may be presented upon install. Please note
  that Microsoft is ending support for these operating systems in January 2020.

* WinPcap API-compatible mode no longer installs a separate filter driver.
  Packet.DLL will translate NPF device names so that they are all serviced by
  the npcap.sys driver. The npf.sys driver has been removed. See
  [#1812](http://issues.nmap.org/1812).

* Improve the speed of `pcap_findalldevs` by reducing the number of calls to
  `GetAdaptersAddresses`, removing a redundant function call, and improving
  buffer reallocation. Patch by Tomasz Moń
  ([#20](https://github.com/nmap/npcap/pull/20)).

* Temporary DLLs unpacked during installation are now signed with our code
  signing certificate. Certain strict application whitelisting systems were
  complaining about unsigned DLL's loaded from a temporary directory.

* Fixed a bug in the uninstaller preventing downgrades to prior versions of
  Npcap. On 64-bit Windows, the driver file `npcap.sys` was not properly
  removed, and Windows would not replace it with any older version. Fixes
  [#1686](http://issues.nmap.org/1686).

## Npcap 0.9984 [2019-10-30]

* Update libpcap to 1.9.1. See [the libpcap CHANGES
  file](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.9.1/CHANGES)
  for this release. This update addresses several CVE-identified vulnerabilities.

* Address several code quality issues identified by Charles E. Smith of
  Tangible Security using Coverity source code analysis.

* Fixed processing of the "enforced" value for several command-line installer
  options. Fixes [#1719](http://issues.nmap.org/1719).

* The `DisplayName` value in the Uninstall registry key for Npcap no longer
  includes the version number, which has always been available in the
  `DisplayVersion` value. Instead, it will include the product name and
  edition, e.g. "Npcap" or "Npcap OEM". This value will also be recorded in the
  `Edition` value under the npcap service's Parameters registry key.

* Fixed a couple of issues with the
  [DiagReport tool](https://npcap.org/guide/npcap-users-guide.html#npcap-issues-diagreport)
  used for bug report diagnostics: remove extraneous partial output lines
  ([#1760](http://issues.nmap.org/1760)), and avoid relying on the Server
  service to determine privilege level ([#1757](http://issues.nmap.org/1757)).

## Npcap 0.9983 [2019-08-30]

* Npcap can now detect newly-added network adapters without restarting the
  driver. Fixes [#664](http://issues.nmap.org/664).

* Loopback capture and injection no longer requires the Npcap Loopback Adapter
  to be installed. This is a minor API change, so Nmap 7.80 and earlier will
  still require the adapter to do localhost scans, but Wireshark and most other
  software will not require changes. Loopback capture uses the device name
  `NPF_Loopback` instead of `NPF_{GUID}`, where `GUID` has to be looked up in
  the Registry. The Npcap Loopback Adapter can still be installed by selecting
  "Legacy loopback support" in the installer or using the
  `/loopback_support=yes` command-line option. The`LoopbackSupport` Registry
  value will always be 0x00000001.

* The `DltNull` Registry setting and the `/dlt_null` installer option are no
  longer supported. Loopback capture will use the `DLT_NULL` link type as
  described [in the tcpdump
  documentation](https://www.tcpdump.org/linktypes.html). Loopback packet
  injection will also use this link type instead of requiring a dummy Ethernet
  header to be constructed. The `DltNull` Registry value will still be present
  and set to `1` for software that consults this value.

* Some operations like `pcap_stats()` can now be completed even after the
  adapter that was in use is removed. See [#1650](http://issues.nmap.org/1650).

* Fixed a crash that could happen when stopping the driver during a loopback
  traffic capture. Fixes [#1678](http://issues.nmap.org/1678).

## Npcap 0.9982 [2019-07-30]

* Fix the packet statistics functionality used by `pcap_stats()`, which was
  broken in 0.9981. Fixes [#1668](http://issues.nmap.org/1668).

* Rework the flow of packets through the WFP callout driver that implements
  loopback traffic capture. This should prevent clobbering of redirect context
  data reported in [#1529](http://issues.nmap.org/1529).

* Restore the `/dlt_null` installer option to default to "yes" since it has
  been defaulting to "no" since Npcap 0.992. Using `DLT_NULL` for loopback
  capture is slightly more efficient than creating a dummy Ethernet header,
  which was the default before.

## Npcap 0.9981 [2019-07-23]

* When upgrading Npcap, do not uninstall the existing Npcap until the user
  clicks the Install button. Previously, the existing Npcap was uninstalled
  prior to the first options screen, so that canceling the upgrade left no
  working Npcap on the system.

* Redefine the I/O control codes used by Npcap using the `CTL_CODE` macro to
  ensure proper access control and consistent parameter passing. This is not a
  published API, but the change will require that Packet.DLL and the npcap
  driver are the same version.

* Fix a 1-byte overrun in NPFInstall.exe when killing processes with Npcap DLLs
  in use.

* In cases where PacketOpenAdapter is given an adapter name in UTF-16LE,
  translate it to ASCII before doing string operations on it. See
  [#1575](http://issues.nmap.org/1575).

* Significant reorganization of internal data structures to reduce memory use
  and initialization overhead.

## Npcap 0.997 [N/A]

* Internal testing build, no public release.

## Npcap 0.996 [2019-06-15]

* Fix a crash when stopping the npcap driver service, such as when upgrading
  Npcap, `DRIVER_IRQL_NOT_LESS_OR_EQUAL` in `NPF_DetachAdapter`. Since Npcap
  0.994 and 0.995 may crash when upgrading, the installer will offer to disable
  the npcap driver service if it is running, allowing the user to reboot and
  attempt the install again, avoiding a crash. Fixes [#1626](http://issues.nmap.org/1626).

* Ensure the uninstaller for the previous version of Nmap is called when
  upgrading. Npcap 0.95 through 0.995 erroneously skipped this step in simple
  non-silent upgrades, which could cause multiple Npcap Loopback Adapters to be
  installed.

## Npcap 0.995 [2019-05-10]

* Fix a crash reported via Microsoft crash telemetry,
  `DRIVER_IRQL_NOT_LESS_OR_EQUAL` in `NPF_NetworkClassify` introduced in Npcap
  0.994.  Fixes [#1591](http://issues.nmap.org/1591).

## Npcap 0.994 [2019-05-07]

* Fix the installer options screen, which would immediately proceed to
  installation when you clicked on the "Support loopback traffic" option. Fixes
  [#1577](http://issues.nmap.org/1577).

* Use the `/F` option to `SCHTASKS.EXE` in the installer so that the
  `npcapwatchdog` task can be successfully overwritten if it is present, though
  newer uninstallers also remove the task. Fixes [#1580](http://issues.nmap.org/1580).

* Fix the `CheckStatus.bat` script run by the `npcapwatchdog` scheduled task to
  correctly match output of `reg.exe` on non-English systems. Fixes
  [#1582](http://issues.nmap.org/1582).

* Improve synchronization between WFP (Loopback) and NDIS (control) functions
  within the driver, which ought to improve stability during system
  sleep/suspend events, particularly an access violation in
  `NPF_NetworkClassify` observed via Microsoft crash telemetry.

## Npcap 0.993 [2019-04-27]

* Complete the fix for [#1398](http://issues.nmap.org/1398) that was only
  partially applied in Npcap 0.992. Due to this partial fix, the user-provided
  buffer was double-freed, resulting in a `BAD_POOL_CALLER` BSoD. This issue
  was separately reported as [#1568](http://issues.nmap.org/1568), and has been
  issued the identifier CVE-2019-11490.

* Fix output of `pcap_lib_version` to again report "Npcap version 0.993, based
  on libpcap version 1.9.0" instead of "libpcap version 1.9.0 (packet.dll
  version 0.992)". Npcap 0.992 was the only version affected. Fixes
  [#1566](http://issues.nmap.org/1566).

* Fix a regression in loopback capture that was causing the loopback adapter to
  be missing from `pcap_findalldevs` until the driver was manually stopped and
  restarted. Fixes [#1570](http://issues.nmap.org/1570).

* Remove installer interface option "Automatically start the Npcap driver at
  boot time." Command-line and registry settings are still respected, but
  automatic start will be the default for all new installations, since manual
  start results in delays in network connectivity at boot. See
  [#1502](http://issues.nmap.org/1502).

* Avoid interpreting null or uninitialized memory as out-of-band media-specific
  information for purposes of constructing the Radiotap header when capturing
  in raw 802.11 monitor mode. Fixes [#1528](http://issues.nmap.org/1528).

* Ensure the uninstaller removes the `npcapwatchdog` scheduled task.

* Avoid an uninstaller failure if DLLs and executables are in use during
  uninstall by causing them to be deleted at reboot. See
  [#1555](http://issues.nmap.org/1555).

## Npcap 0.992 [2019-03-24]

* Update libpcap to 1.9.0. See [the libpcap CHANGES
  file](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.9.0/CHANGES)
  for this release and [#1506](http://issues.nmap.org/1506).

* Fix a bug in the fix for [#1406](http://issues.nmap.org/1406) that caused
  capture filters to reject all packets when the packet header was offset from
  the start of the kernel data structure.

* Fix a bug in the fix for [#1398](http://issues.nmap.org/1398) that caused
  BSoD (`BAD_POOL_CALLER`) due to mismatch in functions used to allocate and
  free a data structure.

* Remove installer interface option "Use DLT_NULL as the loopback interface'
  link layer protocol instead of DLT_EN10MB." Command-line and registry
  settings are still respected, but `DLT_NULL` will be the default for all new
  installations.

* Remove installer interface option "Support 802.1Q VLAN tag when capturing and
  sending data," which was unsupported for three years. Support may be restored
  in future releases, but the option has not had any effect in earlier
  installers.

## Npcap 0.991 [2019-03-14]

* Fix a bug in the BPF packet filter engine that caused capture filters with
  byte offsets to reject packets due to fragmentation within `NET_BUFFER`
  structures. See [#1406](http://issues.nmap.org/1406) and
  [#1438](http://issues.nmap.org/1438).

* Fix a bug that caused several network device drivers to crash when using the
  `pcap_sendqueue_transmit` function, due to queued network packets being
  allocated from paged memory that paged out before the drivers accessed it.
  See [#1398](http://issues.nmap.org/1398).

* Fix a crash (`SYSTEM_EXCEPTION_NOT_HANDLED_M`) in `WSKCloseSocket` due to
  double-free, reported via Microsoft crash telemetry.

* Fix a BSOD inherited from WinPcap triggered when `PacketGetStats` is called
  with low system resources. See [#1517](http://issues.nmap.org/1517).

* Properly quote the path to the `CheckStatus.bat` script in the
  `npcapwatchdog` scheduled task. See [#1513](http://issues.nmap.org/1513).

* Fix errors when installing in WinPcap API-compatible mode over WinPcap when
  Npcap install directory does not already exist. See
  [#1456](http://issues.nmap.org/1456).

## Npcap 0.99-r9 [2019-01-22]

* Install a scheduled task at startup to check whether the Npcap Loopback
  Adapter has been removed and restore it. Windows 10 feature updates remove
  the Adapter. See [#1416](http://issues.nmap.org/1416).

* Package the correct driver version. On some platforms, the Npcap 0.99-r8
  installer would install the Npcap 0.99-r7 driver.

* Fix a crash (`REFERENCE_BY_POINTER`) in `NPF_ReleaseOpenInstanceResources`
  reported via Microsoft crash telemetry. See [#1419](http://issues.nmap.org/1419).

## Npcap 0.99-r8 [2018-12-17]

* Revert to using `SERVICE_SYSTEM_START` for the "Automatically start Npcap at
  boot" option. The previous value, `SERVICE_AUTO_START` had been introduced as
  a workaround for network interruption on Windows 7 that was finally solved in
  Npcap 0.99-r7. See [#1208](http://issues.nmap.org/1208).

* Removed extra Registry keywords from Npcap Loopback Adapter which were
  causing it to not appear properly in Windows API calls.
  Fixes [#1368](http://issues.nmap.org/1368).

* Detect in-use WinPcap installations before attempting to overwrite DLLs.
  Offer to terminate the processes just as we do for in-use Npcap.

* [Improved documentation](https://npcap.org/guide/) based on WinPcap
  documentation including updates for Npcap changes. Example code builds on
  Visual Studio 2015 and works with Npcap. Npcap SDK 1.01 includes these changes.

* Fix a crash in `NPF_RegisterCallouts` reported via Microsoft crash telemetry
  caused by a failure when opening the Npcap Loopback Adapter for packet
  capture.

* On Windows 8 and Server 2012, Npcap will rebind to network adapters after
  installation to ensure a more complete fix to
  [#1031](http://issues.nmap.org/1031).

## Npcap 0.99-r7 [2018-07-05]

* Fixed the installer so that Npcap in WinPcap API-compatible mode can do
  loopback capture. This capability is not guaranteed for future releases, but
  was only missing from 0.99-r3 to 0.99-r6. Native-mode Npcap was unaffected.
  Fixes [#1213](http://issues.nmap.org/1213)

* Added a script, `FixInstall.bat`, to fix common problems with installations,
  such as those caused by Windows 10 feature upgrades.
  See [#1216](http://issues.nmap.org/1216)

* Improved stability by restoring certain passthrough NDIS callbacks that are
  not used, but appear to cause connectivity problems if omitted.
  See [#1208](http://issues.nmap.org/1208).

## Npcap 0.99-r6 [2018-06-12]

* Fixed installation on Windows 8 and Server 2012 so that Npcap is able to
  capture on adapters without requiring a reboot. Fixes
  [#1031](http://issues.nmap.org/1031).

* Fixed loss of networking on Windows 7 when Npcap was configured to start at
  boot. Using `AUTO_START` instead of `SYSTEM_START` for the Npcap driver
  service solves the problem. Fixes [#1208](http://issues.nmap.org/1208).

* Fixed a crash reported via Microsoft crash telemetry,
  `DRIVER_IRQL_NOT_LESS_OR_EQUAL` in `NPF_IOControl` when setting
  `OID_GEN_CURRENT_LOOKAHEAD`. Fixes [#1194](http://issues.nmap.org/1194).

* Fixed certain interactions between processes with open Npcap handles that
  could allow one process to stop other running captures from receiving
  packets. Fixes [#1035](http://issues.nmap.org/1035).

## Npcap 0.99-r5 [2018-05-01]

* Restored installer code to silently uninstall WinPcap if silent installation
  in WinPcap API-compatible mode is needed (Npcap OEM only).

* Removed several optional passthrough driver functions that can be handled
  more efficiently by NDIS, since Npcap was not using them.

* Added validation of IRP parameters for additional security.

* Fixed a crash reported via Microsoft crash telemetry,
  `DRIVER_IRQL_NOT_LESS_OR_EQUAL` in `NPF_SendCompleteExForEachOpen` when the
  system is suspended. Fixes [#1193](http://issues.nmap.org/1193).

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
