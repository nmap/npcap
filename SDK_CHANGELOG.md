## Unreleased changes

* Renamed the `SKF_AD_*` constants to `NPCAP_AD_*` to avoid confusion with code
  that may expect the same values or ordering as the constants defined by
  Linux. The old names are still conditionally defined for convenience.

* Defined additional modes for `PacketSetMode()`/`pcap_setmode()`:
  `MODE_SENDTORX` and `MODE_SENDTORX_CLEAR` to enable and disable the SendToRx
  feature independent of systemwide Registry setting.
  Requires Npcap 1.83 driver or later.

* Enable nanosecond-precision timestamps on a packet handle using
  `PACKET_MODE_NANO` with `PacketSetMode()`. Requires Npcap 1.83 driver or later.

* Added new constants for `PacketGetInfo()`: `NPF_GETINFO_MODES` returns
  supported mode bits for `PacketSetMode()`. `NPF_GETINFO_STATS` retrieves
  performance statistics for the filter module. `NPF_GETINFO_MODDBG` gets
  internal debugging info unique to a filter module. These require Npcap 1.84
  driver or later.

## Npcap SDK 1.15 [2025]

* Added a new function, `PacketGetInfo()`. This uses the `PACKET_OID_DATA`
  structure to issue information requests to the Npcap driver. Currently
  defined requests are `NPF_GETINFO_VERSION`, `NPF_GETINFO_CONFIG`, and
  `NPF_GETINFO_BPFEXT`.

* Using `PacketGetInfo()` with `NPF_GETINFO_BPFEXT` allows user code to
  determine which BPF extensions are supported by the driver. The first
  extensions supported by the driver will be `SKF_AD_VLAN_TAG` and
  `SKF_AD_VLAN_TAG_PRESENT`, which have the same meanings as the Linux kernel's
  BPF extensions of the same names.

* Moved Npcap's BPF definitions to `npcap-bpf.h` and other definitions to
  `npcap-defs.h` to allow them to be used independently of `Packet32.h`. They
  are included by `Packet32.h`, so there should be no need to change existing
  code.

## Npcap SDK 1.14 [2022-08-18]

* Restored `PacketLibraryVersion` export. It is still preferred to use
  `PacketGetVersion()`

## Npcap SDK 1.13 [2022-06-21]

* Added SAL annotations to most function prototypes and several struct fields
  in `Packet32.h`

* The undocumented `char PacketLibraryVersion[]` export has been removed from
  Npcap 1.70 and later. The `PacketGetVersion()` function is the documented way
  to get the runtime version of the Packet.dll library.

* PacketGetNetType() now always sets the LinkSpeed field to 0. Many adapters
  did not support the OID that was being used to get the link speed, and
  libpcap (Npcap's published API) does not pass this information through, so
  there should be no impact on the majority of software. Software that needs
  link speed may use `pcap_oid_get_request()` or `GetAdaptersAddresses()` to
  get the information.

## Npcap SDK 1.12 [2021-12-06]

* Added this changelog.

* Included wpcap.lib for ARM64.

* Updated `Examples-pcap/pcap_filter` to show modern API usage with
  `pcap_create()` and `pcap_activate()`.

* Removed documentation and examples for the "kernel dump" feature of WinPcap,
  which has never been supported by Npcap and was disabled in WinPcap 3.1. The
  `Packet32.h` functions which supported this mode have been marked as
  deprecated.

## Npcap SDK 1.11 [2021-09-03]

* Fix an issue with libpcap header files which required VS 2015 or later. This
  change was made to accommodate a few existing licensees. We strongly
  recommend using a currently-supported compiler version to build software with Npcap.

* Added `const` qualifiers to input parameters for several `Packet32.h` functions.

## Npcap SDK 1.10 [2021-06-22]

* ARM64 libs for Packet.dll added.

* Updated documentation.

## Npcap SDK 1.07 [2021-03-10]

* Updated libpcap headers to 1.10.1 from 1.9.1. See [the libpcap CHANGES
  file](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10/CHANGES)
  and issue [#276](http://issues.npcap.org/276) for notable changes.

* Added `Packet32.h` functions to set per-handle time source and precision.
  This supports libpcap function `pcap_set_tstamp_type()` on Npcap 1.20 and
  later.


----
Earlier changes not tracked.
