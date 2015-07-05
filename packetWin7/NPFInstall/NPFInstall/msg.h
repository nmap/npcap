//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//
// General
//
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: MSG_USAGE
//
// MessageText:
//
// %1 Usage: %1 [-r] [-m:\\<machine>] <command> [<arg>...]
// For more information, type: %1 help
//
#define MSG_USAGE                        0x0000EA60L

//
// MessageId: MSG_FAILURE
//
// MessageText:
//
// %1 failed.
//
#define MSG_FAILURE                      0x0000EA61L

//
// MessageId: MSG_COMMAND_USAGE
//
// MessageText:
//
// %1: Invalid use of %2.
// For more information, type: %1 help %2
//
#define MSG_COMMAND_USAGE                0x0000EA62L

//
// HELP
//
//
// MessageId: MSG_HELP_LONG
//
// MessageText:
//
// Device Console Help:
// %1 [-r] [-m:\\<machine>] <command> [<arg>...]
// -r           Reboots the system only when a restart or reboot is required.
// <machine>    Specifies a remote computer. 
// <command>    Specifies a Devcon command (see command list below).
// <arg>...     One or more arguments that modify a command.
// For help with a specific command, type: %1 help <command>
//
#define MSG_HELP_LONG                    0x0000EAC4L

//
// MessageId: MSG_HELP_SHORT
//
// MessageText:
//
// %1!-20s! Display Devcon help.
//
#define MSG_HELP_SHORT                   0x0000EAC5L

//
// MessageId: MSG_HELP_OTHER
//
// MessageText:
//
// Unknown command.
//
#define MSG_HELP_OTHER                   0x0000EAC6L

//
// CLASSES
//
//
// MessageId: MSG_CLASSES_LONG
//
// MessageText:
//
// Devcon Classes Command
// Lists all device setup classes. Valid on local and remote computers.
// %1 [-m:\\<machine>] %2
// <machine>    Specifies a remote computer.
// Class entries have the format <name>: <descr>
// where <name> is the class name and <descr> is the class description.
//
#define MSG_CLASSES_LONG                 0x0000EB28L

//
// MessageId: MSG_CLASSES_SHORT
//
// MessageText:
//
// %1!-20s! List all device setup classes.
//
#define MSG_CLASSES_SHORT                0x0000EB29L

//
// MessageId: MSG_CLASSES_HEADER
//
// MessageText:
//
// Listing %1!u! setup classes on %2.
//
#define MSG_CLASSES_HEADER               0x0000EB2AL

//
// MessageId: MSG_CLASSES_HEADER_LOCAL
//
// MessageText:
//
// Listing %1!u! setup classes.
//
#define MSG_CLASSES_HEADER_LOCAL         0x0000EB2BL

//
// LISTCLASS
//
//
// MessageId: MSG_LISTCLASS_LONG
//
// MessageText:
//
// Devcon Listclass Command
// Lists all devices in the specified setup classes. Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <class> [<class>...]
// <machine>    Specifies a remote computer.
// <class>      Specifies a device setup class.
// Device entries have the format <instance>: <descr>
// where <instance> is a unique instance of the device and <descr> is the device description.
//
#define MSG_LISTCLASS_LONG               0x0000EB8CL

//
// MessageId: MSG_LISTCLASS_SHORT
//
// MessageText:
//
// %1!-20s! List all devices in a setup class.
//
#define MSG_LISTCLASS_SHORT              0x0000EB8DL

//
// MessageId: MSG_LISTCLASS_HEADER
//
// MessageText:
//
// Listing %1!u! devices in setup class "%2" (%3) on %4.
//
#define MSG_LISTCLASS_HEADER             0x0000EB8EL

//
// MessageId: MSG_LISTCLASS_HEADER_LOCAL
//
// MessageText:
//
// Listing %1!u! devices in setup class "%2" (%3).
//
#define MSG_LISTCLASS_HEADER_LOCAL       0x0000EB8FL

//
// MessageId: MSG_LISTCLASS_NOCLASS
//
// MessageText:
//
// There is no "%1" setup class on %2.
//
#define MSG_LISTCLASS_NOCLASS            0x0000EB90L

//
// MessageId: MSG_LISTCLASS_NOCLASS_LOCAL
//
// MessageText:
//
// There is no "%1" setup class on the local machine.
//
#define MSG_LISTCLASS_NOCLASS_LOCAL      0x0000EB91L

//
// MessageId: MSG_LISTCLASS_HEADER_NONE
//
// MessageText:
//
// There are no devices in setup class "%1" (%2) on %3.
//
#define MSG_LISTCLASS_HEADER_NONE        0x0000EB92L

//
// MessageId: MSG_LISTCLASS_HEADER_NONE_LOCAL
//
// MessageText:
//
// There are no devices in setup class "%1" (%2).
//
#define MSG_LISTCLASS_HEADER_NONE_LOCAL  0x0000EB93L

//
// FIND
//
//
// MessageId: MSG_FIND_LONG
//
// MessageText:
//
// Devcon Find Command
// Finds devices with the specified hardware or instance ID. Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <id> [<id>...]
// %1 [-m:\\<machine>] %2 =<class> [<id>...]
// <machine>    Specifies a remote computer.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
// Device entries have the format <instance>: <descr>
// where <instance> is the unique instance of the device and <descr> is the device description.
//
#define MSG_FIND_LONG                    0x0000EBF0L

//
// MessageId: MSG_FIND_SHORT
//
// MessageText:
//
// %1!-20s! Find devices.
//
#define MSG_FIND_SHORT                   0x0000EBF1L

//
// MessageId: MSG_FIND_TAIL_NONE
//
// MessageText:
//
// No matching devices found on %1.
//
#define MSG_FIND_TAIL_NONE               0x0000EBF2L

//
// MessageId: MSG_FIND_TAIL_NONE_LOCAL
//
// MessageText:
//
// No matching devices found.
//
#define MSG_FIND_TAIL_NONE_LOCAL         0x0000EBF3L

//
// MessageId: MSG_FIND_TAIL
//
// MessageText:
//
// %1!u! matching device(s) found on %2.
//
#define MSG_FIND_TAIL                    0x0000EBF4L

//
// MessageId: MSG_FIND_TAIL_LOCAL
//
// MessageText:
//
// %1!u! matching device(s) found.
//
#define MSG_FIND_TAIL_LOCAL              0x0000EBF5L

//
// MessageId: MSG_FINDALL_LONG
//
// MessageText:
//
// Devcon Findall Command
// Finds devices with the specified hardware or instance ID, including devices
// that are not currently attached. Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <id> [<id>...]
// %1 [-m:\\<machine>] %2 =<class> [<id>...]
// <machine>    Specifies a remote computer.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
// Device entries have the format <instance>: <descr>
// where <instance> is the unique instance of the device and <descr> is the description.
//
#define MSG_FINDALL_LONG                 0x0000EBF6L

//
// MessageId: MSG_FINDALL_SHORT
//
// MessageText:
//
// %1!-20s! Find devices, including those that are not currently attached.
//
#define MSG_FINDALL_SHORT                0x0000EBF7L

//
// MessageId: MSG_STATUS_LONG
//
// MessageText:
//
// Devcon Status Command
// Lists the running status of devices with the specified hardware or instance ID.
// Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <id> [<id>...]
// %1 [-m:\\<machine>] %2 =<class> [<id>...]
// <machine>    Specifies a remote computer.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_STATUS_LONG                  0x0000EBF8L

//
// MessageId: MSG_STATUS_SHORT
//
// MessageText:
//
// %1!-20s! List running status of devices.
//
#define MSG_STATUS_SHORT                 0x0000EBF9L

//
// MessageId: MSG_DRIVERFILES_LONG
//
// MessageText:
//
// Devcon Driverfiles Command
// List installed driver files for devices with the specified hardware or
// instance ID. Valid only on the local computer.
// %1 %2 <id> [<id>...]
// %1 %2 =<class> [<id>...]
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_DRIVERFILES_LONG             0x0000EBFAL

//
// MessageId: MSG_DRIVERFILES_SHORT
//
// MessageText:
//
// %1!-20s! List installed driver files for devices.
//
#define MSG_DRIVERFILES_SHORT            0x0000EBFBL

//
// MessageId: MSG_RESOURCES_LONG
//
// MessageText:
//
// Devcon Resources Command
// Lists hardware resources of devices with the specified hardware or instance ID.
// Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <id> [<id>...]
// %1 [-m:\\<machine>] %2 =<class> [<id>...]
// <machine>    Specifies a remote computer. 
// <class>      Specifies a device setup class.
// Examples of <id>:
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_RESOURCES_LONG               0x0000EBFCL

//
// MessageId: MSG_RESOURCES_SHORT
//
// MessageText:
//
// %1!-20s! List hardware resources for devices.
//
#define MSG_RESOURCES_SHORT              0x0000EBFDL

//
// MessageId: MSG_HWIDS_LONG
//
// MessageText:
//
// Devcon Hwids Command
// Lists hardware IDs of all devices with the specified hardware or instance ID.
// Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <id> [<id>...]
// %1 [-m:\\<machine>] %2 =<class> [<id>...]
// <machine>    Specifies a remote computer.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_HWIDS_LONG                   0x0000EBFEL

//
// MessageId: MSG_HWIDS_SHORT
//
// MessageText:
//
// %1!-20s! List hardware IDs of devices.
//
#define MSG_HWIDS_SHORT                  0x0000EBFFL

//
// MessageId: MSG_STACK_LONG
//
// MessageText:
//
// Devcon Stack Command
// Lists the expected driver stack of devices with the specified hardware
// or instance ID. PnP calls each driver's AddDevice routine when building
// the device stack. Valid on local and remote computers.
// %1 [-m:\\<machine>] %2 <id> [<id>...]
// %1 [-m:\\<machine>] %2 =<class> [<id>...]
// <machine>    Specifies a remote computer.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_STACK_LONG                   0x0000EC00L

//
// MessageId: MSG_STACK_SHORT
//
// MessageText:
//
// %1!-20s! List expected driver stack for devices.
//
#define MSG_STACK_SHORT                  0x0000EC01L

//
// ENABLE
//
//
// MessageId: MSG_ENABLE_LONG
//
// MessageText:
//
// Devcon Enable Command
// Enables devices with the specified hardware or instance ID. Valid only on
// the local computer. (To reboot when necessary, include -r.)
// %1 [-r] %2 <id> [<id>...]
// %1 [-r] %2 =<class> [<id>...]
// -r           Reboots the system only when a restart or reboot is required.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_ENABLE_LONG                  0x0000EC54L

//
// MessageId: MSG_ENABLE_SHORT
//
// MessageText:
//
// %1!-20s! Enable devices.
//
#define MSG_ENABLE_SHORT                 0x0000EC55L

//
// MessageId: MSG_ENABLE_TAIL_NONE
//
// MessageText:
//
// No devices were enabled, either because the devices were not found, 
// or because the devices could not be enabled.
//
#define MSG_ENABLE_TAIL_NONE             0x0000EC56L

//
// MessageId: MSG_ENABLE_TAIL_REBOOT
//
// MessageText:
//
// The %1!u! device(s) are ready to be enabled. To enable the devices, restart the devices or
// reboot the system .
//
#define MSG_ENABLE_TAIL_REBOOT           0x0000EC57L

//
// MessageId: MSG_ENABLE_TAIL
//
// MessageText:
//
// %1!u! device(s) are enabled.
//
#define MSG_ENABLE_TAIL                  0x0000EC58L

//
// DISABLE
//
//
// MessageId: MSG_DISABLE_LONG
//
// MessageText:
//
// Devcon Disable Command
// Disables devices with the specified hardware or instance ID.
// Valid only on the local computer. (To reboot when necesary, Include -r .)
// %1 [-r] %2 <id> [<id>...]
// %1 [-r] %2 =<class> [<id>...]
// -r           Reboots the system only when a restart or reboot is required.
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_DISABLE_LONG                 0x0000ECB8L

//
// MessageId: MSG_DISABLE_SHORT
//
// MessageText:
//
// %1!-20s! Disable devices.
//
#define MSG_DISABLE_SHORT                0x0000ECB9L

//
// MessageId: MSG_DISABLE_TAIL_NONE
//
// MessageText:
//
// No devices were disabled, either because the devices were not found,
// or because the devices could not be disabled.
//
#define MSG_DISABLE_TAIL_NONE            0x0000ECBAL

//
// MessageId: MSG_DISABLE_TAIL_REBOOT
//
// MessageText:
//
// The %1!u! device(s) are ready to be disabled. To disable the devices, restart the
// devices or reboot the system .
//
#define MSG_DISABLE_TAIL_REBOOT          0x0000ECBBL

//
// MessageId: MSG_DISABLE_TAIL
//
// MessageText:
//
// %1!u! device(s) disabled.
//
#define MSG_DISABLE_TAIL                 0x0000ECBCL

//
// RESTART
//
//
// MessageId: MSG_RESTART_LONG
//
// MessageText:
//
// Devcon Restart Command
// Restarts devices with the specified hardware or instance ID.
// Valid only on the local computer. (To reboot when necesary, Include -r .)
// %1 [-r] %2 <id> [<id>...]
// %1 [-r] %2 =<class> [<id>...]
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_RESTART_LONG                 0x0000ED1CL

//
// MessageId: MSG_RESTART_SHORT
//
// MessageText:
//
// %1!-20s! Restart devices.
//
#define MSG_RESTART_SHORT                0x0000ED1DL

//
// MessageId: MSG_RESTART_TAIL_NONE
//
// MessageText:
//
// No devices were restarted, either because the devices were not found,
// or because the devices could not be restarted.
//
#define MSG_RESTART_TAIL_NONE            0x0000ED1EL

//
// MessageId: MSG_RESTART_TAIL_REBOOT
//
// MessageText:
//
// The %1!u! device(s) are ready to be restarted. To restart the devices, reboot the system.
//
#define MSG_RESTART_TAIL_REBOOT          0x0000ED1FL

//
// MessageId: MSG_RESTART_TAIL
//
// MessageText:
//
// %1!u! device(s) restarted.
//
#define MSG_RESTART_TAIL                 0x0000ED20L

//
// REBOOT
//
//
// MessageId: MSG_REBOOT_LONG
//
// MessageText:
//
// %1 %2
// Reboots the local computer as part of a planned hardware installation.
//
#define MSG_REBOOT_LONG                  0x0000ED80L

//
// MessageId: MSG_REBOOT_SHORT
//
// MessageText:
//
// %1!-20s! Reboot the local computer.
//
#define MSG_REBOOT_SHORT                 0x0000ED81L

//
// MessageId: MSG_REBOOT
//
// MessageText:
//
// Rebooting the local computer.
//
#define MSG_REBOOT                       0x0000ED82L

//
// DUMP
//
//
// MessageId: MSG_DUMP_PROBLEM
//
// MessageText:
//
// The device has the following problem: %1!02u!
//
#define MSG_DUMP_PROBLEM                 0x0000EDE8L

//
// MessageId: MSG_DUMP_PRIVATE_PROBLEM
//
// MessageText:
//
// The driver reported a problem with the device.
//
#define MSG_DUMP_PRIVATE_PROBLEM         0x0000EDE9L

//
// MessageId: MSG_DUMP_STARTED
//
// MessageText:
//
// Driver is running.
//
#define MSG_DUMP_STARTED                 0x0000EDEAL

//
// MessageId: MSG_DUMP_DISABLED
//
// MessageText:
//
// Device is disabled.
//
#define MSG_DUMP_DISABLED                0x0000EDEBL

//
// MessageId: MSG_DUMP_NOTSTARTED
//
// MessageText:
//
// Device is currently stopped.
//
#define MSG_DUMP_NOTSTARTED              0x0000EDECL

//
// MessageId: MSG_DUMP_NO_RESOURCES
//
// MessageText:
//
// Device is not using any resources.
//
#define MSG_DUMP_NO_RESOURCES            0x0000EDEDL

//
// MessageId: MSG_DUMP_NO_RESERVED_RESOURCES
//
// MessageText:
//
// Device has no reserved resources.
//
#define MSG_DUMP_NO_RESERVED_RESOURCES   0x0000EDEEL

//
// MessageId: MSG_DUMP_RESOURCES
//
// MessageText:
//
// Device is currently using the following resources:
//
#define MSG_DUMP_RESOURCES               0x0000EDEFL

//
// MessageId: MSG_DUMP_RESERVED_RESOURCES
//
// MessageText:
//
// Device has the following reserved resources:
//
#define MSG_DUMP_RESERVED_RESOURCES      0x0000EDF0L

//
// MessageId: MSG_DUMP_DRIVER_FILES
//
// MessageText:
//
// Driver installed from %2 [%3]. %1!u! file(s) used by driver:
//
#define MSG_DUMP_DRIVER_FILES            0x0000EDF1L

//
// MessageId: MSG_DUMP_NO_DRIVER_FILES
//
// MessageText:
//
// Driver installed from %2 [%3]. The driver is not using any files.
//
#define MSG_DUMP_NO_DRIVER_FILES         0x0000EDF2L

//
// MessageId: MSG_DUMP_NO_DRIVER
//
// MessageText:
//
// No driver information available for the device.
//
#define MSG_DUMP_NO_DRIVER               0x0000EDF3L

//
// MessageId: MSG_DUMP_HWIDS
//
// MessageText:
//
// Hardware IDs:
//
#define MSG_DUMP_HWIDS                   0x0000EDF4L

//
// MessageId: MSG_DUMP_COMPATIDS
//
// MessageText:
//
// Compatible IDs:
//
#define MSG_DUMP_COMPATIDS               0x0000EDF5L

//
// MessageId: MSG_DUMP_NO_HWIDS
//
// MessageText:
//
// No hardware/compatible IDs found for this device.
//
#define MSG_DUMP_NO_HWIDS                0x0000EDF6L

//
// MessageId: MSG_DUMP_NO_DRIVERNODES
//
// MessageText:
//
// No driver nodes found for this device.
//
#define MSG_DUMP_NO_DRIVERNODES          0x0000EDF7L

//
// MessageId: MSG_DUMP_DRIVERNODE_HEADER
//
// MessageText:
//
// Driver node #%1!u!:
//
#define MSG_DUMP_DRIVERNODE_HEADER       0x0000EDF8L

//
// MessageId: MSG_DUMP_DRIVERNODE_INF
//
// MessageText:
//
// Inf file is %1
//
#define MSG_DUMP_DRIVERNODE_INF          0x0000EDF9L

//
// MessageId: MSG_DUMP_DRIVERNODE_SECTION
//
// MessageText:
//
// Inf section is %1
//
#define MSG_DUMP_DRIVERNODE_SECTION      0x0000EDFAL

//
// MessageId: MSG_DUMP_DRIVERNODE_DESCRIPTION
//
// MessageText:
//
// Driver description is %1
//
#define MSG_DUMP_DRIVERNODE_DESCRIPTION  0x0000EDFBL

//
// MessageId: MSG_DUMP_DRIVERNODE_MFGNAME
//
// MessageText:
//
// Manufacturer name is %1
//
#define MSG_DUMP_DRIVERNODE_MFGNAME      0x0000EDFCL

//
// MessageId: MSG_DUMP_DRIVERNODE_PROVIDERNAME
//
// MessageText:
//
// Provider name is %1
//
#define MSG_DUMP_DRIVERNODE_PROVIDERNAME 0x0000EDFDL

//
// MessageId: MSG_DUMP_DRIVERNODE_DRIVERDATE
//
// MessageText:
//
// Driver date is %1
//
#define MSG_DUMP_DRIVERNODE_DRIVERDATE   0x0000EDFEL

//
// MessageId: MSG_DUMP_DRIVERNODE_DRIVERVERSION
//
// MessageText:
//
// Driver version is %1!u!.%2!u!.%3!u!.%4!u!
//
#define MSG_DUMP_DRIVERNODE_DRIVERVERSION 0x0000EDFFL

//
// MessageId: MSG_DUMP_DRIVERNODE_RANK
//
// MessageText:
//
// Driver node rank is %1!u!
//
#define MSG_DUMP_DRIVERNODE_RANK         0x0000EE00L

//
// MessageId: MSG_DUMP_DRIVERNODE_FLAGS
//
// MessageText:
//
// Driver node flags are %1!08X!
//
#define MSG_DUMP_DRIVERNODE_FLAGS        0x0000EE01L

//
// MessageId: MSG_DUMP_DRIVERNODE_FLAGS_OLD_INET_DRIVER
//
// MessageText:
//
// Inf came from the Internet
//
#define MSG_DUMP_DRIVERNODE_FLAGS_OLD_INET_DRIVER 0x0000EE02L

//
// MessageId: MSG_DUMP_DRIVERNODE_FLAGS_BAD_DRIVER
//
// MessageText:
//
// Driver node is marked "BAD"
//
#define MSG_DUMP_DRIVERNODE_FLAGS_BAD_DRIVER 0x0000EE03L

//
// MessageId: MSG_DUMP_DRIVERNODE_FLAGS_INF_IS_SIGNED
//
// MessageText:
//
// Inf is digitally signed
//
#define MSG_DUMP_DRIVERNODE_FLAGS_INF_IS_SIGNED 0x0000EE04L

//
// MessageId: MSG_DUMP_DRIVERNODE_FLAGS_OEM_F6_INF
//
// MessageText:
//
// Inf was installed by using F6 during text mode setup
//
#define MSG_DUMP_DRIVERNODE_FLAGS_OEM_F6_INF 0x0000EE05L

//
// MessageId: MSG_DUMP_DRIVERNODE_FLAGS_BASIC_DRIVER
//
// MessageText:
//
// Driver provides basic functionality when no signed driver is available.
//
#define MSG_DUMP_DRIVERNODE_FLAGS_BASIC_DRIVER 0x0000EE06L

//
// MessageId: MSG_DUMP_DEVICESTACK_UPPERCLASSFILTERS
//
// MessageText:
//
// Upper class filters:
//
#define MSG_DUMP_DEVICESTACK_UPPERCLASSFILTERS 0x0000EE07L

//
// MessageId: MSG_DUMP_DEVICESTACK_UPPERFILTERS
//
// MessageText:
//
// Upper filters:
//
#define MSG_DUMP_DEVICESTACK_UPPERFILTERS 0x0000EE08L

//
// MessageId: MSG_DUMP_DEVICESTACK_SERVICE
//
// MessageText:
//
// Controlling service:
//
#define MSG_DUMP_DEVICESTACK_SERVICE     0x0000EE09L

//
// MessageId: MSG_DUMP_DEVICESTACK_NOSERVICE
//
// MessageText:
//
// (none)
//
#define MSG_DUMP_DEVICESTACK_NOSERVICE   0x0000EE0AL

//
// MessageId: MSG_DUMP_DEVICESTACK_LOWERCLASSFILTERS
//
// MessageText:
//
// Class lower filters:
//
#define MSG_DUMP_DEVICESTACK_LOWERCLASSFILTERS 0x0000EE0BL

//
// MessageId: MSG_DUMP_DEVICESTACK_LOWERFILTERS
//
// MessageText:
//
// Lower filters:
//
#define MSG_DUMP_DEVICESTACK_LOWERFILTERS 0x0000EE0CL

//
// MessageId: MSG_DUMP_SETUPCLASS
//
// MessageText:
//
// Setup Class: %1 %2
//
#define MSG_DUMP_SETUPCLASS              0x0000EE0DL

//
// MessageId: MSG_DUMP_NOSETUPCLASS
//
// MessageText:
//
// Device is not set up.
//
#define MSG_DUMP_NOSETUPCLASS            0x0000EE0EL

//
// MessageId: MSG_DUMP_DESCRIPTION
//
// MessageText:
//
// Name: %1
//
#define MSG_DUMP_DESCRIPTION             0x0000EE0FL

//
// MessageId: MSG_DUMP_PHANTOM
//
// MessageText:
//
// Device is not present.
//
#define MSG_DUMP_PHANTOM                 0x0000EE10L

//
// MessageId: MSG_DUMP_STATUS_ERROR
//
// MessageText:
//
// Error retrieving the device's status.
//
#define MSG_DUMP_STATUS_ERROR            0x0000EE11L

//
// INSTALL
//
//
// MessageId: MSG_INSTALL_LONG
//
// MessageText:
//
// Devcon Install Command
// Installs the specified device manually. Valid only on the local computer. 
// (To reboot when necesary, Include -r .)
// %1 [-r] %2 <inf> <hwid>
// <inf>        Specifies an INF file with installation information for the device.
// <hwid>       Specifies a hardware ID for the device.
// -r           Reboots the system only when a restart or reboot is required.
//
#define MSG_INSTALL_LONG                 0x0000EE48L

//
// MessageId: MSG_INSTALL_SHORT
//
// MessageText:
//
// %1!-20s! Install a device manually.
//
#define MSG_INSTALL_SHORT                0x0000EE49L

//
// MessageId: MSG_INSTALL_UPDATE
//
// MessageText:
//
// Device node created. Install is complete when drivers are installed...
//
#define MSG_INSTALL_UPDATE               0x0000EE4AL

//
// UPDATE
//
//
// MessageId: MSG_UPDATE_LONG
//
// MessageText:
//
// Devcon Update Command
// Updates drivers for all devices with the specified hardware ID (<hwid>). 
// Valid only on the local computer. (To reboot when necesary, Include -r .)
// %1 [-r] %2 <inf> <hwid>
// -r           Reboots the system only when a restart or reboot is required.
// <inf>        Specifies an INF file with installation information for the devices.
// <hwid>       Specifies the hardware ID of the devices.
//
#define MSG_UPDATE_LONG                  0x0000EEACL

//
// MessageId: MSG_UPDATE_SHORT
//
// MessageText:
//
// %1!-20s! Update a device manually.
//
#define MSG_UPDATE_SHORT                 0x0000EEADL

//
// MessageId: MSG_UPDATE_INF
//
// MessageText:
//
// Updating drivers for %1 from %2.
//
#define MSG_UPDATE_INF                   0x0000EEAEL

//
// MessageId: MSG_UPDATE
//
// MessageText:
//
// Updating drivers for %1.
//
#define MSG_UPDATE                       0x0000EEAFL

//
// MessageId: MSG_UPDATENI_LONG
//
// MessageText:
//
// %1 [-r] %2 <inf> <hwid>
// Update drivers for devices (Non Interactive).
// This command will only work for local machine.
// Specify -r to reboot automatically if needed.
// <inf> is an INF to use to install the device.
// All devices that match <hwid> are updated.
// Unsigned installs will fail. No UI will be
// presented.
//
#define MSG_UPDATENI_LONG                0x0000EEB0L

//
// MessageId: MSG_UPDATENI_SHORT
//
// MessageText:
//
// %1!-20s! Manually update a device (non interactive).
//
#define MSG_UPDATENI_SHORT               0x0000EEB1L

//
// MessageId: MSG_UPDATE_OK
//
// MessageText:
//
// Drivers installed successfully.
//
#define MSG_UPDATE_OK                    0x0000EEB2L

//
// Driver Package (add/remove/enum)
//
//
// MessageId: MSG_DPADD_LONG
//
// MessageText:
//
// %1 %2 <inf>
// Adds (installs) a third-party (OEM) driver package.
// This command will only work on the local machine.
// <inf> is a full path to the INF of the Driver
// Package that will be installed on this machine.
//
#define MSG_DPADD_LONG                   0x0000EEB3L

//
// MessageId: MSG_DPADD_SHORT
//
// MessageText:
//
// %1!-20s! Adds (installs) a third-party (OEM) driver package.
//
#define MSG_DPADD_SHORT                  0x0000EEB4L

//
// MessageId: MSG_DPDELETE_LONG
//
// MessageText:
//
// %1 [-f] %2 <inf>
// Deletes a third-party (OEM) driver package.
// This command will only work on the local machine.
// [-f] will force delete the driver package, even
// if it is in use by a device.
// <inf> is the name of a published INF on the local
// machine.  This is the value returned from dp_add
// and dp_enum.
//
#define MSG_DPDELETE_LONG                0x0000EEB5L

//
// MessageId: MSG_DPDELETE_SHORT
//
// MessageText:
//
// %1!-20s! Deletes a third-party (OEM) driver package.
//
#define MSG_DPDELETE_SHORT               0x0000EEB6L

//
// MessageId: MSG_DPENUM_LONG
//
// MessageText:
//
// %1 %2
// Lists the third-party (OEM) driver packages installed on this machine.
// This command will only work on the local machine.
// Values returned from dp_enum can be sent to dp_delete 
// to be removed from the machine.
//
#define MSG_DPENUM_LONG                  0x0000EEB7L

//
// MessageId: MSG_DPENUM_SHORT
//
// MessageText:
//
// %1!-20s! Lists the third-party (OEM) driver packages installed on this machine.
//
#define MSG_DPENUM_SHORT                 0x0000EEB8L

//
// MessageId: MSG_DPADD_INVALID_INF
//
// MessageText:
//
// The specified INF path is not valid.
//
#define MSG_DPADD_INVALID_INF            0x0000EEB9L

//
// MessageId: MSG_DPADD_FAILED
//
// MessageText:
//
// Adding the specified driver package to the machine failed.
//
#define MSG_DPADD_FAILED                 0x0000EEBAL

//
// MessageId: MSG_DPADD_SUCCESS
//
// MessageText:
//
// Driver package '%1' added.
//
#define MSG_DPADD_SUCCESS                0x0000EEBBL

//
// MessageId: MSG_DPDELETE_FAILED
//
// MessageText:
//
// Deleting the specified driver package from the machine failed.
//
#define MSG_DPDELETE_FAILED              0x0000EEBCL

//
// MessageId: MSG_DPDELETE_FAILED_IN_USE
//
// MessageText:
//
// Deleting the specified driver package from the machine failed
// because it is in use by a device.
//
#define MSG_DPDELETE_FAILED_IN_USE       0x0000EEBDL

//
// MessageId: MSG_DPDELETE_FAILED_NOT_OEM_INF
//
// MessageText:
//
// Deleting the specified driver package from the machine failed
// because it is not an third-party package.
//
#define MSG_DPDELETE_FAILED_NOT_OEM_INF  0x0000EEBEL

//
// MessageId: MSG_DPDELETE_SUCCESS
//
// MessageText:
//
// Driver package '%1' deleted.
//
#define MSG_DPDELETE_SUCCESS             0x0000EEBFL

//
// MessageId: MSG_DPENUM_NO_OEM_INF
//
// MessageText:
//
// There are no third-party driver packages on this machine.
//
#define MSG_DPENUM_NO_OEM_INF            0x0000EEC0L

//
// MessageId: MSG_DPENUM_LIST_HEADER
//
// MessageText:
//
// The following third-party driver packages are installed on this computer:
//
#define MSG_DPENUM_LIST_HEADER           0x0000EEC1L

//
// MessageId: MSG_DPENUM_LIST_ENTRY
//
// MessageText:
//
// %1
//
#define MSG_DPENUM_LIST_ENTRY            0x0000EEC2L

//
// MessageId: MSG_DPENUM_DUMP_PROVIDER
//
// MessageText:
//
//     Provider: %1
//
#define MSG_DPENUM_DUMP_PROVIDER         0x0000EEC3L

//
// MessageId: MSG_DPENUM_DUMP_PROVIDER_UNKNOWN
//
// MessageText:
//
//     Provider: unknown
//
#define MSG_DPENUM_DUMP_PROVIDER_UNKNOWN 0x0000EEC4L

//
// MessageId: MSG_DPENUM_DUMP_CLASS
//
// MessageText:
//
//     Class: %1
//
#define MSG_DPENUM_DUMP_CLASS            0x0000EEC5L

//
// MessageId: MSG_DPENUM_DUMP_CLASS_UNKNOWN
//
// MessageText:
//
//     Class: unknown
//
#define MSG_DPENUM_DUMP_CLASS_UNKNOWN    0x0000EEC6L

//
// MessageId: MSG_DPENUM_DUMP_VERSION
//
// MessageText:
//
//     Version: %1
//
#define MSG_DPENUM_DUMP_VERSION          0x0000EEC7L

//
// MessageId: MSG_DPENUM_DUMP_VERSION_UNKNOWN
//
// MessageText:
//
//     Version: unknown
//
#define MSG_DPENUM_DUMP_VERSION_UNKNOWN  0x0000EEC8L

//
// MessageId: MSG_DPENUM_DUMP_DATE
//
// MessageText:
//
//     Date: %1
//
#define MSG_DPENUM_DUMP_DATE             0x0000EEC9L

//
// MessageId: MSG_DPENUM_DUMP_DATE_UNKNOWN
//
// MessageText:
//
//     Date: unknown
//
#define MSG_DPENUM_DUMP_DATE_UNKNOWN     0x0000EECAL

//
// MessageId: MSG_DPENUM_DUMP_SIGNER
//
// MessageText:
//
//     Signer: %1
//
#define MSG_DPENUM_DUMP_SIGNER           0x0000EECBL

//
// MessageId: MSG_DPENUM_DUMP_SIGNER_UNKNOWN
//
// MessageText:
//
//     Signer: unknown
//
#define MSG_DPENUM_DUMP_SIGNER_UNKNOWN   0x0000EECCL

//
// REMOVE
//
//
// MessageId: MSG_REMOVE_LONG
//
// MessageText:
//
// Devcon Remove Command
// Removes devices with the specified hardware or instance ID. Valid only on
// the local computer. (To reboot when necesary, Include -r .)
// %1 [-r] %2 <id> [<id>...]
// %1 [-r] %2 =<class> [<id>...]
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_REMOVE_LONG                  0x0000EF10L

//
// MessageId: MSG_REMOVE_SHORT
//
// MessageText:
//
// %1!-20s! Remove devices.
//
#define MSG_REMOVE_SHORT                 0x0000EF11L

//
// MessageId: MSG_REMOVE_TAIL_NONE
//
// MessageText:
//
// No devices were removed.
//
#define MSG_REMOVE_TAIL_NONE             0x0000EF12L

//
// MessageId: MSG_REMOVE_TAIL_REBOOT
//
// MessageText:
//
// The %1!u! device(s) are ready to be removed. To remove the devices, reboot the system.
//
#define MSG_REMOVE_TAIL_REBOOT           0x0000EF13L

//
// MessageId: MSG_REMOVE_TAIL
//
// MessageText:
//
// %1!u! device(s) were removed.
//
#define MSG_REMOVE_TAIL                  0x0000EF14L

//
// RESCAN
//
//
// MessageId: MSG_RESCAN_LONG
//
// MessageText:
//
// Devcon Rescan Command
// Directs Plug and Play to scan for new hardware. Valid on a local or remote computer.
// %1 [-m:\\<machine>]
// <machine>    Specifies a remote computer. 
//
#define MSG_RESCAN_LONG                  0x0000EF74L

//
// MessageId: MSG_RESCAN_SHORT
//
// MessageText:
//
// %1!-20s! Scan for new hardware.
//
#define MSG_RESCAN_SHORT                 0x0000EF75L

//
// MessageId: MSG_RESCAN_LOCAL
//
// MessageText:
//
// Scanning for new hardware.
//
#define MSG_RESCAN_LOCAL                 0x0000EF76L

//
// MessageId: MSG_RESCAN
//
// MessageText:
//
// Scanning for new hardware on %1.
//
#define MSG_RESCAN                       0x0000EF77L

//
// MessageId: MSG_RESCAN_OK
//
// MessageText:
//
// Scanning completed.
//
#define MSG_RESCAN_OK                    0x0000EF78L

//
// DRIVERNODES
//
//
// MessageId: MSG_DRIVERNODES_LONG
//
// MessageText:
//
// Devcon Drivernodes Command
// Lists driver nodes for devices with the specified hardware or instance ID.
// Valid only on the local computer.
// %1 %2 <id> [<id>...]
// %1 %2 =<class> [<id>...]
// <class>      Specifies a device setup class.
// Examples of <id>:
//  *              - All devices
//  ISAPNP\PNP0501 - Hardware ID
//  *PNP*          - Hardware ID with wildcards  (* matches anything)
//  @ISAPNP\*\*    - Instance ID with wildcards  (@ prefixes instance ID)
//  '*PNP0501      - Hardware ID with apostrophe (' prefixes literal match - matches exactly as typed,
//                                                including the asterisk.)
//
#define MSG_DRIVERNODES_LONG             0x0000EFD8L

//
// MessageId: MSG_DRIVERNODES_SHORT
//
// MessageText:
//
// %1!-20s! List driver nodes of devices.
//
#define MSG_DRIVERNODES_SHORT            0x0000EFD9L

//
// CLASSFILTER
//
//
// MessageId: MSG_CLASSFILTER_LONG
//
// MessageText:
//
// Devcon Classfilter Command
// 
// Lists, adds, deletes, and reorders upper and lower filter drivers for a device
// setup class. Changes do not take effect until the affected devices are restarted
// or the machine is rebooted.
// 
// %1 %2 [-r] <class> {upper | lower} [<operator><filter> [<operator><filter>...]]
// <class>      Specifies a device setup class.
// <operator>   Specifies an operation (listed below).
// <filter>     Specifies a class filter driver.
// upper        Identifies an upper filter driver.
// lower        Identifies a lower filter driver.
// 
// To list the upper/lower filter drivers for a class, 
// type:  devcon classfilter <class> {upper | lower}
// 
// The Devcon classfilter command uses subcommands, which consist of an 
// operator (=, @, -, +, !) and a filter driver name.
// 
// The Devcon classfilter command uses a virtual cursor to move through
// the list of filter drivers. The cursor starts at the beginning of the 
// list (before the first filter). Unless returned to the starting position,
// the cursor always moves forward.
// 
// Operators
//  =       Move the cursor to the beginning of the filter driver list (before the
//          first filter driver).
// 
//  @       Position the cursor on the next instance of the specified filter.
// 
//  -       Add before. Insert the specified filter before the filter on which the cursor
//          is positioned. If the cursor is not positioned on a filter, insert the
//          new filter at the beginning of the list. When the subcommand completes, the
//          cursor is positioned on the newly-added filter.
// 
//  +       Add after. Insert the specified filter after the filter on which the cursor
//          is positioned. If the cursor is not positioned on a filter, Devcon inserts the
//          new filter at the end of the list. When the subcommand completes, the cursor
//          cursor is positioned on the newly-added filter.       
// 
//  !       Deletes the next occurrence of the specified filter. When the subcommand 
//          completes, the cursor occupies the position of the deleted filter. 
//          Subsequent - or + subcommands insert a new filter at the cursor position.
// 
// 
// Examples:
// If the upper filters for setup class "foo" are A,B,C,B,D,B,E:
// %1 %2 foo upper @D !B    - deletes the third 'B'.
// %1 %2 foo upper !B !B !B - deletes all three instances of 'B'.
// %1 %2 foo upper =!B =!A  - deletes the first 'B' and the first 'A'.
// %1 %2 foo upper !C +CC   - replaces 'C' with 'CC'.
// %1 %2 foo upper @D -CC   - inserts 'CC' before 'D'.
// %1 %2 foo upper @D +CC   - inserts 'CC' after 'D'.
// %1 %2 foo upper -CC      - inserts 'CC' before 'A'.
// %1 %2 foo upper +CC      - inserts 'CC' after 'E'.
// %1 %2 foo upper @D +X +Y - inserts 'X' after 'D' and 'Y' after 'X'.
// %1 %2 foo upper @D -X -Y - inserts 'X' before 'D' and 'Y' before 'X'.
// %1 %2 foo upper @D -X +Y - inserts 'X' before 'D' and 'Y' between 'X' and 'D'.
//
#define MSG_CLASSFILTER_LONG             0x0000F03CL

//
// MessageId: MSG_CLASSFILTER_SHORT
//
// MessageText:
//
// %1!-20s! Add, delete, and reorder class filters.
//
#define MSG_CLASSFILTER_SHORT            0x0000F03DL

//
// MessageId: MSG_CLASSFILTER_CHANGED
//
// MessageText:
//
// Class filters changed. Restart the devices or reboot the system to make the change effective.
//
#define MSG_CLASSFILTER_CHANGED          0x0000F03EL

//
// MessageId: MSG_CLASSFILTER_UNCHANGED
//
// MessageText:
//
// Class filters unchanged.
//
#define MSG_CLASSFILTER_UNCHANGED        0x0000F03FL

//
// SETHWID
//
//
// MessageId: MSG_SETHWID_LONG
//
// MessageText:
//
// %1 [-m:\\<machine>] %2 <id> [<id>...] := <subcmds>
// %1 [-m:\\<machine>] %2 =<class> [<id>...] := <subcmds>
// Modifies the hardware ID's of the listed devices. This command will only work for root-enumerated devices.
// This command will work for a remote machine.
// Examples of <id> are:
// *                  - All devices (not recommended)
// ISAPNP\PNP0601     - Hardware ID
// *PNP*              - Hardware ID with wildcards (* matches anything)
// @ROOT\*\*          - Instance ID with wildcards (@ prefixes instance ID)
// <class> is a setup class name as obtained from the classes command.
// 
// <subcmds> consists of one or more:
// =hwid              - Clear hardware ID list and set it to hwid.
// +hwid              - Add or move hardware ID to head of list (better match).
// -hwid              - Add or move hardware ID to end of list (worse match).
// !hwid              - Remove hardware ID from list.
// hwid               - each additional hardware id is inserted after the previous.
//
#define MSG_SETHWID_LONG                 0x0000F0A0L

//
// MessageId: MSG_SETHWID_SHORT
//
// MessageText:
//
// %1!-20s! Modify Hardware ID's of listed root-enumerated devices.
//
#define MSG_SETHWID_SHORT                0x0000F0A1L

//
// MessageId: MSG_SETHWID_TAIL_NONE
//
// MessageText:
//
// No hardware ID's modified.
//
#define MSG_SETHWID_TAIL_NONE            0x0000F0A2L

//
// MessageId: MSG_SETHWID_TAIL_SKIPPED
//
// MessageText:
//
// Skipped %1!u! non-root device(s), modified the hardware ID on %2!u! device(s).
//
#define MSG_SETHWID_TAIL_SKIPPED         0x0000F0A3L

//
// MessageId: MSG_SETHWID_TAIL_MODIFIED
//
// MessageText:
//
// Modified the Hardware ID on %1!u! device(s).
//
#define MSG_SETHWID_TAIL_MODIFIED        0x0000F0A4L

//
// MessageId: MSG_SETHWID_NOTROOT
//
// MessageText:
//
// Skipping (Not root-enumerated).
//
#define MSG_SETHWID_NOTROOT              0x0000F0A5L

