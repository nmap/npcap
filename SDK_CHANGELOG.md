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
