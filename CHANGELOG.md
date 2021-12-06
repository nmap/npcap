
## Unreleased changes

* Npcap can now tolerate network disconnections or NDIS stack modifications
  that previously resulted in programs like Wireshark stopping with the error
  "PacketReceivePacket error: The device has been removed. (1617)". This error
  may still be returned, but user programs can consider it a transient error.
  If the network is reconnected, capture can resume on the same handle.
  Fixes [#506](http://issues.npcap.org/506).

* Improved validation for IRP parameters, resolving potential BSoD crashes that
  could be triggered by software interacting directly with the driver's device
  interface. These bugs still affect the last releases of WinPcap. Thanks to Ilja
  Van Sprundel from IOActive for reporting them.

* Fix an issue with NX pool compatibility that caused Npcap 1.50 and 1.55 to
  fail to run on some Windows 7 systems. Fixes [#536](http://issues.npcap.org/536).

* Fix how the installer handles `/option=enforced`, which was broken in Npcap
  1.55. Fixes [#556](http://issues.npcap.org/556).

* Further deprecate the "Legacy loopback support" option: The npcapwatchdog
  scheduled task will not check for the existence of the Npcap Loopback
  Adapter.

* The `/prior_driver` installer option now selects the Npcap 1.30 driver, since
  the Microsoft's cross-certificate expired 30 minutes prior to signing Version
  1.31. See [#536](http://issues.npcap.org/536).

* When installing Npcap in WinPcap API-Compatible mode (the default), the Npcap
  installer will perform the uninstallation of WinPcap directly instead of
  running the WinPcap uninstaller. This prevents the WinPcap uninstaller from
  rebooting the system and allows us to clean up partial or broken installations.

* Replaced a feature of NPFInstall.exe and the SimpleSC.dll NSIS plugin with
  Powershell commands to improve installer size and compatibility.
  May fix [#226](http://issues.npcap.org/226).

## Npcap 1.55 [2021-09-03]

* Npcap installer can now recognize NetCfg status codes indicating that a
  reboot is required (0x0004a020, `NETCFG_S_REBOOT`), and will prompt the user
  to reboot. In silent mode, the installer will return code 3010 (0x0bc2,
  `ERROR_SUCCESS_REBOOT_REQUIRED`) to indicate this result. Fixes [#224](http://issues.npcap.org/224).

* The silent installer (only available in Nmap OEM) now offers better
  control over when to remove and reinstall an existing Npcap. You can
  specify your Npcap version number or feature requirements with the
  new `/require_version`, `/require_features`, and `/force`
  options. Software with strict requirements might re-run at startup
  to ensure that Npcap hasn't been uninstalled or changed. If Npcap
  still exists and meets your requirements, the installer quits
  immediately. These new options are documented at
  https://nmap.org/npcap/guide/npcap-users-guide.html and Nmap OEM is
  described at https://nmap.org/npcap/#oem. Fixes
  [#523](http://issues.npcap.org/523).

* Fixed an installation failure (0xe0000247) on Windows 8.1/Server 2012 R2 and
  earlier systems which have not updated root certificates. The root certificates
  are now installed to the Roots trust store. Fixes [#233](http://issues.npcap.org/233).

* Fixed an issue since Npcap 1.30 where broadcast and subnet masks for adapters
  returned by `pcap_findalldevs()` were in host byte order, displaying values
  like "0.240.255.255". Fixes [#525](http://issues.npcap.org/525).

* Libpcap 1.10.1 has been updated to include some recent changes to the libpcap-1.10
  release branch which extend support to adapters with the NdisMediumIP media type,
  including Wireguard Wintun virtual adapters. Fixes [#173](http://issues.npcap.org/173).

* Added specific bad-value checks for issues originating in other drivers which
  may be incorrectly attributed to Npcap. These checks, in combination with
  additional `const` qualifiers, should serve as assurance that Npcap is not
  modifying traffic during capture and cannot be responsible for such crashes.

* Powershell commands launched by the installer are now run with the
  `-NoProfile` option. Fixes [#529](http://issues.npcap.org/529).

* Npcap SDK 1.11 released. This includes upstream libpcap changes to allow building with older
  Visual Studio versions, as well as minor changes to add const qualifiers to parameters to several
  Packet.dll functions.  Fixes [#518](http://issues.npcap.org/518).

* Npcap installer now uses Unicode internally. This may result in mixed-encoding install.log files.

## Npcap 1.50 [2021-06-22]

* Fixed [#513](http://issues.npcap.org/513) which prevented Npcap 1.40 from installing.

* Npcap can now be installed on Windows 10 for ARM64 devices. Both ARM64 and
  x86 DLLs will be installed, allowing existing x86 applications such as Nmap
  or Wireshark to run without modification.

* Npcap SDK 1.10 release coincides with this release, providing updated
  documentation and libs for ARM64.

* Npcap code now passes Microsoft's Static Driver Verifier for NDIS drivers and
  Visual Studio's Code Analysis "AllRules" ruleset. A couple of minor and
  extremely-improbable bugs were fixed in addition to general code cleanup and annotation.

* On Windows 8 and 8.1, the Npcap driver has been updated to NDIS 6.30,
  supporting network stack improvements like RSC and QoS. Windows 10 still uses
  NDIS 6.50 and Windows 7 uses NDIS 6.20.

* Npcap is no longer distributed with SHA-1 digital signatures. Windows 7 and
  Server 2008 R2 will require KB4474419 in order to install Npcap. All other
  platforms support SHA-2 digital signatures by default.

* Streamlined loopback packet injection to avoid using Winsock Kernel (WSK)
  sockets. This removes a significant amount of complexity and overhead.

* Due to Microsoft's [deprecation of cross-signed root certificates for kernel-mode code signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/deprecation-of-software-publisher-certificates-and-commercial-release-certificates),
  Npcap 1.40 may not install correctly on Windows versions prior to Windows 10.
  Our testing did not show any issues, but users who experience installation
  failures may use the `/prior_driver=yes` installation option to install the
  Npcap 1.31 driver instead, which has no such issues.

* The "npcapwatchdog" scheduled task, which ensures the Npcap driver service is
  configured to start at boot, is now installed with a description when
  possible (Windows 7 does not support creating scheduled tasks via PowerShell).
  Fixes [#498](http://issues.npcap.org/498).

* All PowerShell scripts installed or used during installation are now digitally signed.

* Fix an issue where installation under Citrix Remote Access or other
  situations would fail with the message "Installer runtime error 255 at
  76539962, Could not load SimpleSC.dll". Fixes [#226](http://issues.npcap.org/226).

* Ensure driver signature can be validated on systems without Internet access
  by installing the entire certificate chain, including the chain for the
  timestamp counter-signature. This should address [#233](http://issues.npcap.org/233).

* Fix an issue with comparing adapter names retrieved from the Registry. This
  prevented Npcap 1.31 from being used for SendToRx and other less-used
  features. Fixes [#311](http://issues.npcap.org/311).

* Npcap driver no longer excludes adapters based on media type, which may allow
  capture on some devices that were previously unavailable.

## Npcap 1.40 [2021-06-21]

* This release was retracted due to installer issues. See [#513](http://issues.npcap.org/513).

## Npcap 1.31 [2021-04-21]

* Fix a bug with the non-default legacy loopback capture support that caused
  all requests to open a capture handle to open the loopback capture instead.
  It is recommended to not select "Legacy loopback support" at installation
  unless you know your application relies on it. Fixes [#302](http://issues.npcap.org/302).

* For Windows 10 and Server 2016 and later, restore the ability to capture
  traffic on VMware VMnet interfaces such as the host-only and NAT virtual
  networks. This will be restored for other supported Windows versions in a
  later release. Fixes [#304](http://issues.npcap.org/304).

## Npcap 1.30 [2021-04-09]

* Restore raw WiFi frame capture support, which had been broken in a few ways
  since Npcap 0.9983. Additional improvements enable `PacketSetMonitorMode()`
  for non-admin-privileged processes, allowing Wireshark to correctly enable
  monitor mode via checkbox without requiring WlanHelper.exe.

* Fixed WlanHelper.exe to correctly set modes and channels for adapters, if run
  with Administrator privileges. Fixes [#122](http://issues.npcap.org/122).

* Improved speed of `pcap_findalldevs()` by using fewer calls to
  `GetAdaptersAddresses()` and avoiding direct Registry inspection. The new
  method may result in more adapters being available for capture than
  previously reported. See [#169](http://issues.npcap.org/169).

* Updated Packet.dll to use modern `HeapAlloc()` allocation, faster than the
  legacy `GlobalAlloc()` inherited from WinPcap.

* Improve error reporting from `PacketGetAdapterNames()` and related functions.

## Npcap 1.20 [2021-03-10]

* Upgrade wpcap.dll to libpcap 1.10. This change enables software to use
  `pcap_set_tstamp_type()` to set the packet capture time source and precision
  per capture handle. The currently-supported types (see
  [`pcap-tstamp`](https://nmap.org/npcap/guide/wpcap/pcap-tstamp.html)) are:
  * `PCAP_TSTAMP_HOST_HIPREC_UNSYNCED` - default, maps to `TIMESTAMPMODE_SINGLE_SYNCHRONIZATION`
  * `PCAP_TSTAMP_HOST_LOWPREC` - maps to `TIMESTAMPMODE_QUERYSYSTEMTIME`
  * `PCAP_TSTAMP_HOST_HIPREC` - maps to `TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE`

* Fix an issue preventing `WlanHelper.exe` from changing WiFi parameters for
  adapters which caused the error message "makeOIDRequest::My_PacketOpenAdapter
  error". Fixes [#122](http://issues.npcap.org/122) and several other reports
  of the same issue.

* Fixed an issue that prevented NDIS protocol drivers from reducing the
  hardware packet filter, even if the removed bits/filters were only set by
  that protocol driver initially. This caused network interruptions on VMware systems.
  Fixes [#106](http://issues.npcap.org/106).

* Fixed an issue with `pcap_sendqueue_transmit()` that caused it to busy-wait
  in an attempt to synchronize packet sends with pcap timestamps, even when the
  program did not request synchronization. Fixes [#113](http://issues.npcap.org/113).

* The installer will now safely remove and replace broken installations due to
  [#268](http://issues.npcap.org/268).

* Upgraded installer to NSIS 3, which improves compatibility with modern Windows versions.

* Added application manifests to several installer tools and removed Windows
  Vista from the manifests of others, improving compatibility.

## Npcap 1.10 [2020-12-11]

* Fixed an issue where our upgrade uninstaller would trigger the
  [#1924](https://issues.nmap.org/1924) BSoD crash when upgrading from Npcap 0.9988 or older to
  version 0.9996 or greater. Fixes [#268](http://issues.npcap.org/268).

* Improved handling of large packets when a very small user buffer size is specified, which could
  lead to stalled captures and dropped packets.

* Fix a packet corruption issue when one capture handle sets a snaplen of exactly 256 bytes and
  another sets a snaplen of greater than 256 bytes and the packet size exceeds 256 bytes.

* Fix accounting of free space in the kernel buffer so that bugs like the previous one do not cause
  space to be permanently lost, leading to dropped packets. Instead, use assertions to catch this
  condition in testing with the debug build.

* Check that the npcap driver service is configured for `SYSTEM_START` in the `npcapwatchdog`
  scheduled task and correct it if necessary. Windows feature updates can modify this value.

## Npcap 1.00 [2020-09-25]

* After more than 7 years of development and 170 previous public releases, the
  Nmap Project is delighted to release Npcap version 1.00!

* New Packet.dll function `PacketGetTimestampModes()` to retrieve supported
  packet timestamping modes. These do not currently vary by adapter, but
  `TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE` is not supported on Windows 7, for
  example. Fixes [#174](http://issues.npcap.org/174).

* Npcap driver is now only signed with SHA256 signatures on platforms other
  than Windows 7, which may resolve signature validation issues on some
  systems. The Windows 7 driver is signed with SHA-1 signatures only.

## Npcap 0.9997 [2020-08-25]

* Fix an integer underflow in the amount of free buffer space available leading
  to excessive memory consumption. Fixes [#223](http://issues.npcap.org/223).

* Significantly reduced per-packet memory overhead for packets in the kernel capture buffer.

* Replaced object pool/slab allocator with Windows lookaside lists, improving
  performance by avoiding spinlocks and allowing the system to adjust memory
  consumption.

## Npcap 0.9996 [2020-08-07]

* Fix a runaway memory leak triggered by low-resources condition leading to
  system hangs. Fixes [#213](http://issues.npcap.org/213).

* Fix a BSoD crash in `NPF_Read` in some high-traffic cases. Fixes [#206](http://issues.npcap.org/206).

* Fix a handle leak in Packet.dll when enumerating interfaces. Fixes [#26](http://issues.npcap.org/26).

* Fix an inconsistency between return value and IRP completion status in
  `NPF_Read` when an adapter is removed. Driver Verifier would cause a bugcheck
  (BSoD) in this case, and pcap API functions would not detect an error.
  Fixes [#217](http://issues.npcap.org/217)

* Improved performance by reusing allocated packet data buffers and
  implementing `DISPATCH_LEVEL` tracking throughout the driver to speed up lock
  acquisition.

* When upgrading from compatible recent versions (currently Npcap 0.9985 and
  newer), the installer will unpack a new `Uninstall.exe` and `NPFInstall.exe`
  prior to removing the existing installation. This resolves issues with the
  uninstallation process such as were common in Npcap 0.9991 through 0.9994.

* Upgraded build system to VisualStudio 2019 and WDK 10.0.18362.0

## Npcap 0.9995 [2020-07-10]

* Fix a BSoD crash in `NPF_Read` when NDIS filter module is detached from the
  adapter. Fixes [#194](http://issues.npcap.org/194)

* On Windows 10, the Npcap driver has been updated to NDIS 6.50 and Windows 10
  WFP compatibility, supporting network stack improvements like RSC.
  Fixes [#196](http://issues.npcap.org/196).

* Correctly obey maximum frame size for an adapter by querying
  `OID_GEN_MAXIMUM_TOTAL_SIZE` instead of using MTU, which does not include
  space for the link layer header. Fixes [#186](http://issues.npcap.org/186).

* Fix detection of processes using Npcap resources during uninstall or upgrade.
  The fix for [#2015](http://issues.nmap.org/2015) had broken this so such
  processes were not terminated, leading to failed installations.

* Obey snaplen (`pcap_set_snaplen()`) even if a packet filter is not set. This
  is a backported change from upstream libpcap that corrects a deficiency that
  has been present in all previous versions of WinPcap and Npcap.
  Fixes [#201](http://issues.npcap.org/201).

* Improvements to object pool/slab allocator to allow nonpaged memory to be
  freed when not in use.

* When installing Npcap OEM in silent mode, avoid running `C:\Uninstall.exe` if
  no existing Npcap installation is present.

## Npcap 0.9994 [2020-06-12]

* Fix a BSoD crash in `NPF_ReleaseOpenInstanceResources` due to miscounting of
  number of open Loopback capture instances. Fixes [#185](http://issues.npcap.org/185).

* Fix corrupted and missing packets in Npcap 0.9992 and 0.9993 due to reusing a
  data structure that already contained packet data.

* Ensure our SHA-1 code signing certificate is also installed on systems which
  may require it. This was preventing installation on older platforms since
  Npcap 0.9991.

* Fix a crash in `NPFInstall.exe` that happened when trying to rebind Npcap to
  the network stack as part of some installations. Reported by Microsoft App
  Assure ISV Outreach Team.

* When multiple packets are indicated in a single `FilterReceiveNetBufferLists`
  callback, only get a single timestamp for all of them. Avoids extra calls to
  KeQueryPerformanceCounter or KeQuerySystemTimePrecise which only ended up
  measuring Npcap processing delay, not actual packet arrival time.

* Fix a potential NULL pointer deref issue in `Objpool.h` macros if an
  allocation were to fail and return a NULL pointer.

* Fix parsing of `pnputil.exe` output that resulted in Npcap drivers not being
  cleared from the DriverStore before installing or upgrading. This led to
  older drivers being preferred in some cases, such as installing an unsigned
  driver in test mode.

* Move all capture- and injection-related initialization code out of
  `NPF_OpenAdapter`, improving efficiency of operations like listing adapters
  or performing OID requests without starting a full capture.

* Added SAL annotations to most driver functions to improve static analysis.
  Found one issue related to using a NULL NDIS handle in an allocation
  function, which is not supported on Windows 7.

* Allow driver to load even if there is a problem initializing loopback capture
  or injection functions. The loopback capture device will simply be
  unavailable in that case.

## Npcap 0.9993 [2020-06-05]

* Fix a BSoD crash in `NPF_DoInternalRequest` triggered by suspending the
  system while a capture is running. Added source annotations to allow static
  analysis to catch bugs like this in the future. Fixes [#181](http://issues.npcap.org/181).

* Fix a bug introduced in Npcap 0.9992 which caused loopback capture to fail if
  any loopback capture had been previously started and finished.

* Fix packet length calculation for loopback capture. The packet length was
  being counted twice, leading to junk data being appended to captured packets.

* If installation fails for any reason other than a failure to uninstall the
  previous version of Npcap, the current version's uninstaller will be used to
  clean up any partial installation. The only remaining files will be the
  `install.log` and `NPFInstall.log` in the  Npcap installation directory.

* Replaced ReadWriteLock mechanisms with improved `NDIS_RW_LOCK_EX` new in NDIS
  6.20 for improved performance.

* Moved object pool for captured packets from the filter module (adapter)
  object to the open instance (pcap handle) to allow memory to be recovered
  after a capture is closed.

## Npcap 0.9992 [2020-06-03]

* Npcap issues are now tracked on [their own Github Issues
  page](http://issues.npcap.org), separate from Nmap issues. Many existing
  issues have been migrated, and issue numbers may have changed.

* Rewrote the kernel packet capture buffer code again to avoid requiring a
  separate worker thread. Instead, captured packets are held directly in a
  synchronized queue. The worker thread introduced in Npcap 0.9991 was unable
  to keep up with the volume of packet requests, leading to buffer bloat and
  reduced performance.

* Avoid initializing loopback capture-related functions and processing packets
  as soon as an adapter is opened. This will improve performance since adapters
  are opened as part of listing adapters.

* Fix a crash in NPFInstall.exe when terminating processes which are using
  Npcap resources. This could lead to failed installations and message windows
  about "A LWF & WFP driver installation tool has stopped working."

* Update Npcap from NDIS 6.10 to NDIS 6.20, which limits its compatibility to
  Windows 7 and higher. Closes [#167](http://issues.npcap.org/167).

* Fix a bug in Npcap 0.9991 which prevented packets from being captured until a
  BPF filter had been set. Fixes [#168](http://issues.npcap.org/168) (migrated
  from nmap/nmap#2037).

* Allow capture statistics and captured packets remaining in the buffer to be
  retrieved when an adapter is removed. Fixes [nmap/nmap#2036](https://issues.nmap.org/2036).

* Use WMI instead of the Windows 10-only `Get-NetAdapter` Powershell cmdlet in
  the DiagReport tool. Fixes [nmap/nmap#611](https://issues.nmap.org/611).

## Npcap 0.9991 [2020-05-04]

* Switched our code signing certificate back to DigiCert after some users found
  older Windows versions could not validate the signature on our driver for
  versions 0.9985 through 0.9990.  The driver is again dual-signed with SHA-1
  and SHA-2 certificates. See [#2012](https://issues.nmap.org/2012).

* Major changes to management of Npcap driver's circular packet buffer,
  switching from per-CPU unshared segments to a single worker thread managing a
  queue of work items. This improves buffer utilization, reduces the amount of
  time spent processing in the network stack, and should reduce packet loss.
  See [#1967](https://issues.nmap.org/1967).

* Several performance-related improvements to the NDIS filter driver: Switched
  from SpinLocks to ReadWriteLocks for several crucial shared data structures,
  which will improve performance by reducing resource contention on
  multiprocessor systems, and introduced an object-pool allocation pattern for
  several frequently-used short-lifetime objects, improving performance by
  reducing memory allocations.

* Again restore "unused" NDIS filter callbacks which cause Windows 7 to lose
  connectivity when they are removed. See [#1998](https://issues.nmap.org/1998).

* Include debug symbols for `wpcap.dll` in our debug symbols zip file at
  https://npcap.org/#download . Fixes [#1844](https://issues.nmap.org/1844).

* Fixed [#1996](https://issues.nmap.org/1996): heap corruption in
  `NPFInstall.exe` since Npcap 0.9989 leading to hung installs when the "raw
  802.11 traffic" option was checked.

* Fixed [#2014](https://issues.nmap.org/2014): Npcap OEM silent install
  produced a dialog when installing over an existing installation of the same
  version.

* Uninstaller improvements related to removing the installation directory,
  properly killing processes using Npcap DLLs, not leaving a partial
  installation if a step fails. Fixes [#2013](https://issues.nmap.org/2013)
  and [#2015](https://issues.nmap.org/2015).

## Npcap 0.9990 [2020-04-04]

* Improve compatibility with WinPcap's behavior regarding injected traffic.
  WinPcap uses inefficient loopback to capture all outbound traffic, but allows
  `PacketSetLoopbackBehavior()` to avoid this for injected traffic. Because of
  Npcap's more efficient design, injected traffic was never looped back up to
  protocol drivers, causing problems for some users who relied on this behavior.
  Now, injected traffic follows the same path as with WinPcap, though ordinary
  traffic is unaffected. For highest efficiency without loopback, use
  `PacketSetLoopbackBehavior(NPF_DISABLE_LOOPBACK)`. Fixes [#1343](https://issues.nmap.org/1343),
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

## Npcap 0.09-r9 []

## Npcap 0.09-r8 []

## Npcap 0.09-r7 []

## Npcap 0.09-r6 []

## Npcap 0.09-r5 []

## Npcap 0.09-r4 []

## Npcap 0.09-r3 []

## Npcap 0.09-r2 []

## Npcap 0.09-r13 []

## Npcap 0.09-r12 []

## Npcap 0.09-r11 []

## Npcap 0.09-r10 []

## Npcap 0.09 []

## Npcap 0.08-r9 []

## Npcap 0.08-r8 []

## Npcap 0.08-r7 []

## Npcap 0.08-r6 []

## Npcap 0.08-r5 []

## Npcap 0.08-r4 []

## Npcap 0.08-r3 []

## Npcap 0.08-r2 []

## Npcap 0.08-r10 []

## Npcap 0.08 []

## Npcap 0.07-r9 []

## Npcap 0.07-r8 []

## Npcap 0.07-r7 []

## Npcap 0.07-r6 []

## Npcap 0.07-r5 []

## Npcap 0.07-r4 []

## Npcap 0.07-r3 []

## Npcap 0.07-r2 []

## Npcap 0.07-r17 []

## Npcap 0.07-r16 []

## Npcap 0.07-r15 []

## Npcap 0.07-r14 []

## Npcap 0.07-r13 []

## Npcap 0.07-r12 []

## Npcap 0.07-r11 []

## Npcap 0.07-r10 []

## Npcap 0.07 []

## Npcap 0.06-r19 []

## Npcap 0.06-r18 []

## Npcap 0.06-r17 []

## Npcap 0.06-r16 []

## Npcap 0.06-r15 []

## Npcap 0.06-r14 []

## Npcap 0.06-r13 []

## Npcap 0.06-r12 []

## Npcap 0.06-r11 []

## Npcap 0.06-r10 []

## Npcap 0.06-r9 []

## Npcap 0.06-r8 []

## Npcap 0.06-r7 []

## Npcap 0.06-r6 []

## Npcap 0.06-r5 []

## Npcap 0.06-r4 [2016-03-04]

* The uninstallation window won't close itself now.

* Fixed the problem that the uninstallation process won't end in the Task Manager.

* System restore point will not be created in the uninstallation phase.

* Improved the text display of the installer.

## Npcap 0.06-r3 [2016-03-03]

* Improved the creating system restore point support. Now Npcap installer will
  create a Windows system restore point named Before Npcap %VERSION% installs
  before actual installation process and create a point named Before Npcap
  %VERSION% uninstalls before uninstallation.

## Npcap 0.06-r2 [2016-03-01]

* Made the loopback feature optional in the installer. This option is checked
  by default.

* Improved the creating system restore point logic by removing nested
  creation. A modified SysRestore plug-in is used:
  https://github.com/hsluoyz/SysRestore

## Npcap 0.06 [2016-02-29]

* Fixed the bug reported by yyjdelete that Npcap causes BSoD if the user tries to disable the adapter while sending packets.

## Npcap 0.05-r16 [2016-02-29]

* Added creating system restore point support. Now the installer has added an
  option called Create a system restore point before installing Npcap. It this
  option is checked, Npcap installer will create a Windows system restore
  point named Before installing Npcap before actual installation
  process. Returning back to this point will roll back all changes made by
  Npcap. Note: this option is NOT checked by default.

## Npcap 0.05-r15 [2016-02-28]

* Added debug symbols support. Now Npcap will release new versions shipping
  with the corresponding debug symbols. These PDB files will help debugging
  BSoDs and user-mode crashes of Npcap binaries.  See
  https://github.com/nmap/npcap/releases/tag/v0.05-r15.

## Npcap 0.05-r14 [2016-02-25]

* Fixed the driver signing error in Win7. We used the legacy SHA1 code signing
  cert to sign the Npcap driver in Win7, so no need for Win7 users to install
  KB3033929 patch any more.

* This version Npcap is supposed to have fixed all signing errors, so it will
  successfully install on all the platforms: Vista, Win7, Win8, Win8.1 and
  Win10 without any prerequisites.

## Npcap 0.05-r13 [2016-02-20]

* Fixed a driver signing error in Vista. See
  https://github.com/nmap/npcap/releases/tag/v0.05-r13.

## Npcap 0.05-r12 [2016-02-16]

* Signed the installer with better signing method

## Npcap 0.05-r11 [2016-02-16]

* Npcap 0.05 r11: Added firewall (Block-Rx) support. See
  https://github.com/nmap/npcap/releases/tag/v0.05-r11.

## Npcap 0.05-r10 [2016-02-04]

* Added different Timestamp modes support like original WinPcap.  See https://github.com/nmap/npcap/releases/tag/v0.05-r10

## Npcap 0.05-r9 [2016-02-04]

* Updated wpcap.dll from VS2005 to VS2013 and Packet.dll, NPFInstall.exe and
  NPcapHelper.exe from VS2010 to VS2013.

* Additionally, I rolled back the driver signing improvement in 0.05
  r8. Because it will show a Program Compatibility Assistant window said a
  well signed driver is needed. However, it's not true because npcap driver
  runs well by testing net start npf. To avoid this false message, I rolled
  back to the original signing commands.

## Npcap 0.05-r8 [2016-02-01]

* Now Npcap driver will be signed in both SHA1 and SHA256 digest algorithms
  and with timestamp. This improvement will help the driver installation on
  Vista and Win7. This is an issue reported by Graham Bloice (see graham's
  answer in
  https://ask.wireshark.org/questions/46689/failed-to-create-npcap-service).

## Npcap 0.05-r7 [2016-01-28]

* Now send-to-Rx adapters can be multiple. The string specified in registry's SendToRx value should be semicolon-separated.

An example for one send-to-Rx adapter:
'\Device\{754FC84C-EFBC-4443-B479-2EFAE01DC7BF}

An example for two send-to-Rx adapters:
'\Device\{754FC84C-EFBC-4443-B479-2EFAE01DC7BF};\Device\{F5A00000-E19A-4D17-B6D9-A23FE1852573}

## Npcap 0.05-r6 [2016-01-27]

* Now Npcap can have a send-to-Rx adapter. The send-to-Rx adapter will inject
  all its packets to "Receive Path" (Rx) instead of normal "Send Path"
  (Tx). So that instead of sending traffic to the network, the adapter will
  pretend to receive the injected traffic from the network in this way.

* Currently only one send-to-Rx adapter is supported by specifying SendToRx
  value in Npcap driver service's registry key (need to restart the driver to
  take effect).

* Npcap driver service's registry key is usually in:
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npf. In this key. You
  need to manually create a REG_SZ value named SendToRx, the value is the name
  of the adapter you want to be send-to-Rx adapter. The name is usually like
  format of \Device\{F5A00000-E19A-4D17-B6D9-A23FE1852573}. You can query this
  value using Nmap's nmap --iflist command, you will get a similar value like
  \Device\NPF_{F5A00000-E19A-4D17-B6D9-A23FE1852573}, but they are NOT THE
  SAME. You need to remove the NPF_ in this string and copy it to registry's
  SendToRx value. Then reboot the driver by net stop npf and net start npf.

## Npcap 0.05-r5 [2016-01-11]

* Fixed the bug reported by Nuno Antonio Dias Ferreira that Npcap fails to
  retrieve the adapter list using NPF registry way.

## Npcap 0.05-r4 [2015-12-17]

* Fixed the bug reported by Tenzin Rigden that Npcap installer fails to
  install correct files in /S silent mode.

## Npcap 0.05-r3 [2015-11-25]

* Added Npcap's support for Vista, Npcap now will prepare separate binaries
  for Vista.

## Npcap 0.05-r2 [2015-11-05]

* Fixed the bug reported by Amos Sheldon that Npcap causes BSoD:
  ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY when using Wireshark on Win8, 10 x86.

## Npcap 0.05 [2015-09-11]

* Added the "DON'T LOOPBACK" feature, if software set
  PacketSetLoopbackBehavior() by disable, self-sent packets will not be
  received again.

* Built the installer using NSIS with strlen_8192, so system "PATH" will be
  updated normally in most cases (PATH is less than 8192).

* Added 128 CPU core support for Npcap, or Npcap will cause BSoD when running
  on 128-core system.

* Improved the appearance and text of the installer.

## Npcap 0.04-r9 [2015-08-31]

* Fixed the bug that Npcap can't capture real loopback traffic after system is
  resumed from standby.

## Npcap 0.04-r8 [2015-08-25]

* Now PCAP_IF_LOOPBACK flag in pcap_if_t struct will be set for "Npcap
  Loopback Adapter" both for DLT_NULL mode and Fake Ethernet mode.

## Npcap 0.04-r7 [2015-08-24]

* PCAP_IF_LOOPBACK flag in pcap_if_t struct will be set for "Npcap Loopback
  Adapter" now, only for DLT_NULL mode

* Fixed the bug that DLT_NULL mode can't be disabled in the driver.

## Npcap 0.04-r6 [2015-08-23]

* Packet.dll will return NdisMediumNull for "Npcap Loopback Adapter" now.

## Npcap 0.04-r5 [2015-08-21]

* Finished the DLT_NULL protocol support. But there's a problem that Wireshark
  didn't parse the loopback packets right, need fix.

## Npcap 0.04-r4 [2015-08-21]

* Npcap driver will return 65550 as "Maximum Packet Size" instead of default
  1514 for "Npcap Loopback Adapter", which refers to Linux implementation.

## Npcap 0.04-r3 [2015-08-18]

* Fixed the bug reported by Pascal Quantin that WSK code fails to init if it
  is run without Administrator right, the effect is Npcap loopback adapter
  can't be opened.

## Npcap 0.04-r2 [2015-08-16]

* Modified wpcap.dll version to 0.04, and improved the error trace message for
  Winsock Kernel socket operations.

## Npcap 0.04 [2015-08-15]

* Fixed the SYSTEM_SERVICE_EXCEPTION BSoD caused by NdisFOidRequest call, this
  may help to fix the BAD_POOL_CALLER BSoD (I said "may" because this BSoD
  can't be reproduced).

* Modified Nmap and Nping to be able to send loopback packets on Windows OS,
  here's a bug, Nmap still can't see reply packets. But the request and reply
  packets can be seen in Wireshark.

## Npcap 0.03-r6 [2015-08-06]

* Changed to static linked.

## Npcap 0.03-r5 [2015-08-06]

* Npcap can send loopback packets now!

## Npcap 0.03-r4 [2015-08-05]

* WSKTest can send IPv4 and IPv6 loopback packets based on Ethernet header
  now.

* Added IPv6 send support for WSKTest.

* WSKTest can send a self-constructed ICMPv4 request packet now

* Fixed the INF file lacking section issue in WSKTest.

* Updated WSKTest from VS 2013 to VS 2015.

## Npcap 0.03-r3 [2015-08-03]

## Npcap 0.03-r2 [2015-07-30]

* Improved WSK send code, update code format

## Npcap 0.03 [2015-07-27]

## Npcap 0.02-r4 [2015-07-26]

## Npcap 0.02-r3 [2015-07-24]

## Npcap 0.02-r2 [2015-07-22]

* Fixed the bug that "Npcap Loopback Adaprer" renaming fails in Win10 non-English editions.

## Npcap 0.02 [2015-07-22]

* Solve the "system error 2" issue

## Npcap 0.01-r2 [2015-07-19]

## Npcap 0.01 [2015-06-23]

* Add option to restrict Npcap usage to Windows users with admin rights rather
  than all users.

## Npcap Birthday (First Public Code Checkin)! [2013-06-24]

* Npcap's birthday! While Gordon "Fyodor" Lyon and Yang Luo had been working
  on the idea for a couple of months, June 24, 2013 was the date that Yang
  checked in the first actual code with the Npcap name!

