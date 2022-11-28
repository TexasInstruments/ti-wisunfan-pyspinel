# TI Wi-SUN FAN Spinel CLI Reference

The TI Wi-SUN FAN Spinel CLI exposes the configuration and management APIs running on a TI Wi-SUN FAN Network Co-Processor (NCP) via a command line interface. This tool is primarily suitable for manual experimentation with controlling TI Wi-SUN FAN NCP instances and is NOT meant for expanding into production grade driver software for TI Wi-SUN FAN NCP devices.

This tool will be helpful for following purposes:

1. As a path to automated testing and performing field trials with TI Wi-SUN FAN NCP running on TI SimpleLink devices.
2. As a simple debugging tool for NCP builds of TI-WiSUN FAN stack.

## System Requirements

| Language | Minimum Version |
| -------- | --------------- |
| Python   | 3.6.8           |

### Package installation

Install dependencies:

```
$ sudo apt install python3-pip
$ pip3 install --user pyserial ipaddress
```

Install Pyspinel:

```
# From pyspinel root
$ sudo python3 setup.py install
```

## Usage

### NAME

    spinel-cli.py - shell tool for controlling TI Wi-SUN FAN NCP instances

### SYNOPSIS

    spinel-cli.py [-hub]

### DESCRIPTION

```
    -h, --help
    	Show this help message and exit

    -u <UART>, --uart=<UART>
       	Open a serial connection to the TI Wi-SUN NCP device
	where <UART> is a device path such as "/dev/ttyUSB0".

    -b <BAUDRATE>, --baudrate=<BAUDRATE>
        Specify a serial connection baudrate. By default set to 115200.

    --rtscts
        Enable the serial connection hardware flow control. By default disabled.

```

## Quick start

The TI Wi-SUN FAN spinel-cli tool provides an intuitive command line interface for interacting with and controlling TI SimpleLink devices running TI Wi-SUN FAN stack software.

First, build the TI Wi-SUN FAN NCP Border router and router node binaries from the SDK. Flash the images onto the devices.

Then run the Pyspinel CLI:

```
$ cd <path-to-pyspinel>
$ spinel-cli.py -u /dev/ttyUSB0
spinel-cli > ncpversion
TIWISUNFAN/1.0.0; RELEASE; Jul  9 2021 20:26:46
Done
spinel-cli > panid 0x1234
Done
spinel-cli > ifconfig up
Done
spinel-cli > wisunstack start
Done
spinel-cli > routerstate
1
Scanning for suitable network
Done
spinel-cli >
```

## Command reference

### Generic CLI commands

Below are the generic CLI commands supported by TI Wi-SUN FAN pySpinel CLI:

- [help](#help)
- [?](#help)
- [v](#v)
- [exit](#exit)
- [quit](#quit)
- [q](#quit)
- [clear](#clear)
- [history](#history)

#### help

Display all commands supported by TI Wi-SUN spinel-cli.

```bash
spinel-cli > help

Available commands (type help <name> for more information):
============================================================        
asyncchlist       exit              ncpversion       revokeDevice   
bcchfunction      getoadfwver       networkname      role
bcdwellinterval   getoadstatus      numconnected     routerstate    
bcinterval        help              nverase          rssi
broadcastchlist   history           panid            startoad       
ccathreshold      hwaddress         phymodeid        txpower        
ch0centerfreq     ifconfig          ping             ucchfunction   
chspacing         interfacetype     protocolversion  ucdwellinterval
clear             ipv6addresstable  q                unicastchlist  
coap              macfilterlist     quit             v
connecteddevices  macfiltermode     region           wisunstack
dodagroute        multicastlist     reset
```

#### help \<command\>

Display detailed help on a specific command.

```bash
spinel-cli > help ncpversion

ncp version

    Print the build version information.

    > ncpversion
    TIWISUNFAN/1.0; DEBUG; Feb 7 2021 18:22:04
    Done
```

#### v

Display version of TI Wi-SUN spinel-cli tool.

```bash
spinel-cli > v
spinel-cli ver. 0.1.0
Copyright (c) 2016 The OpenThread Authors. Modified by Texas Instruments for TI NCP Wi-SUN devices
```

#### exit

Exit TI Wi-SUN spinel-cli. CTRL+C may also be used.

#### quit

Exit TI Wi-SUN spinel-cli. CTRL+C may also be used.

### clear

Clear screen.

#### history

Display history of most recent commands run.

```bash
spinel-cli > history
ping fd00::1
quit
help
history
```

### TI Wi-SUN specific CLI commands

Below are some commonly used Wi-SUN FAN stack specific commands supported by the TI Wi-SUN FAN pySpinel CLI. For the full list of commands and help on individual commands use the [help](#help) command. Please note that any configuration of the TI Wi-SUN FAN stack should be done before bringing up the interface (ifconfig up) and starting the Wi-SUN FAN stack (wisunstack start).

- [networkname](#networkname)
- [ifconfig](#ifconfig)
- [wisunstack](#wisunstack)
- [routerstate](#routerstate)
- [numconnected](#numconnected)
- [connecteddevices](#connecteddevices)
- [ipv6addresstable](#ipv6addresstable)
- [ping](#ping)
- [multicastlist](#multicastlist)
- [coap](#coap)
- [dodagroute](#dodagroute)
- [rssi](#rssi)
- [getoadfwver](#getoadfwver)
- [startoad](#startoad)
- [getoadstatus](#getoadstatus)
- [setpanidlistjson](#setpanidlistjson)
- [setpanidlist](#setpanidlist)
- [getpanidlist](#getpanidlist)
- [panrediscover](#panrediscover)

#### networkname

Get or set the Wi-SUN FAN network name.

```bash
spinel-cli > networkname Wi-SUN NET
Done
spinel-cli > networkname
Wi-SUN NET
Done
```

#### ifconfig

Bring up or down the Wi-SUN FAN Network Interface. ifconfig down functionality is currently not implemented and will be done in future.

```bash
spinel-cli > ifconfig up
Done
```

#### wisunstack

Display the Operational status of the Wi-SUN FAN network. Can also be used to enable/disable Wi-SUN stack operation and attach to/detach from a Wi-SUN network. "wisunstack start" command should be preceeded by "ifconfig up" command. For router node, even though the stack is brought up, it takes some time for the node to join the network and become operational. Refer to routerstate command for more info. 
wisunstack stop functionality is currently not implemented and will be done in future. Till then use 'reset' command to stop all operations and issue 'ifconfig up' and 'wisunstack start' to start the Wi-SUN network again.

```bash
spinel-cli > wisunstack start
Done
spinel-cli > wisunstack
start
Done
```

#### routerstate

Display the current join state of the Wi-SUN FAN router device. Refer to the FAN 1.0 specification for information on different states of the Wi-SUN FAN router devices before it can join a network and become operational.

```bash
spinel-cli > routerstate
5
Successfully joined and operational
Done
```

#### numconnected

Displays the number of Wi-SUN FAN nodes which have joined to the Wi-SUN FAN border router device.

```bash
spinel-cli > numconnected
2
Done
```

#### connecteddevices

Displays the list of Wi-SUN FAN router nodes which have joined to the Wi-SUN FAN border router device.

```bash
spinel-cli > connecteddevices
List of connected devices currently in routing table:
fd00:7283:7e00:0:212:4b00:1ca1:727a
fd00:7283:7e00:0:212:4b00:1ca6:17ea
Number of connected devices: 2
Done
```

#### ipv6addresstable

Display the Globally Unique DHCP address and Link Local Adress along with prefix length, valid lifetime and preferred lifetime.

```bash
spinel-cli > ipv6addresstable
fd00:7283:7e00:0:212:4b00:1ca1:9463; prefix_len = 64; valid_lifetime = 43129; preferred_lifetime = 21529
fe80::212:4b00:1ca1:9463; prefix_len = 64; valid_lifetime = 4294967295; preferred_lifetime = 4294967295
Done
```

#### ping

Send an ICMPv6 Echo Request. Prints the received ping response. Key in Enter to get the command prompt back, if needed. 

```bash
spinel-cli > ping fd00:7283:7e00:0:212:4b00:1ca1:9463
56 bytes from fd00:7283:7e00:0:212:4b00:1ca1:9463: icmp_seq=50089 hlim=64 time=118ms
```

#### multicastlist

Display, add, or remove IPv6 multicast addresses from the list of multicast addresses the device is subscribed to.

```bash
spinel-cli > multicastlist
ff05::2

spinel-cli > multicastlist remove ff05::2

spinel-cli > multicastlist add ff04::1

spinel-cli > multicastlist
ff04::1
```

#### coap

Send a CoAP GET, PUT, or POST command to get or set the LaunchPad LED state. This is intended to interface with the `coap_node` TI Wi-SUN FAN example.

```bash
spinel-cli > coap fdde:ad00:beef:0:558:f56b:d688:799 get con led
CoAP packet received from fe80::212:4b00:10:50d4: type: 2 (Acknowledgement), token len: 0, code: 2.05 (Content), msg_id: 1
CoAP options: Content-Format (12): b''
RLED state: Off, GLED state: On

spinel-cli > coap fdde:ad00:beef:0:558:f56b:d688:799 post con led --led_state r 1
CoAP packet received from fe80::212:4b00:10:50d4: type: 2 (Acknowledgement), token len: 0, code: 2.04 (Changed), msg_id: 2
CoAP options: Content-Format (12): b''
No CoAP payload

spinel-cli > coap fdde:ad00:beef:0:558:f56b:d688:799 get non led
CoAP packet received from fe80::212:4b00:10:50d4: type: 2 (Acknowledgement), token len: 0, code: 2.04 (Changed), msg_id: 2
CoAP options: Content-Format (12): b''
No CoAP payload
```

#### dodagroute

Displays the full routing path to a device with a specified IPv6 address. Also displays the path cost.

```bash
spinel-cli > dodagroute fd00:7283:7e00:0:212:4b00:10:50d0
Path cost: 2
fd00:7283:7e00:0:212:4b00:10:50d4
fd00:7283:7e00:0:212:4b00:1ca1:758e
fd00:7283:7e00:0:212:4b00:10:50d0
Done
```

#### rssi

Displays the number of neighbor nodes for the current node and rssi of the incoming packets from the neighbor nodes, rssi values reported by the neighbor nodes when the current node sends them packets.

```bash
spinel-cli > rssi
Number of Neighbor Nodes = 2
Neighbor Node RSSI metrics are (EUI, RSSI_IN, RSSI_OUT):
00124b001ca19463, -22.0dBm, -23.0dBm
00124b001ca13486, -32.0dBm, -33.0dBm
Done
```


#### getoadfwver

Get the firmware version of the image on a CoAP OAD-enabled device.

```bash
> getoadfwver fdde:ad00:beef:0:558:f56b:d688:799
Img ID: 123, Platform: 23 (CC1312R7)
OAD firmware version: 1.0.0.0
```

#### startoad

Start a CoAP OAD with a target CoAP OAD-enabled device. Provide the platform type, block size, and image binary path. Note that the target device's OAD method (offchip/onchip) must match the OAD method of the sent oad image binary file.


```bash
> startoad fdde:ad00:beef:0:558:f56b:d688:799 CC1312R7 128 ns_coap_oad_offchip_LP_CC1312R7_tirtos7_ticlang.bin
Sending OAD notification request message
OAD notification response received
OAD upgrade accepted. Starting block transfer
```

#### getoadstatus

Check the status of an ongoing OAD.

```bash
> getoadstatus
Block 0154/2752 sent. Block size: 128. Duration: 0:00:25.804326
```

#### setpanidlistjson

Set the JSON file used to set the panid allow/deny list for new coap nodes joining the network.
If this file is not set or does not exist, you can still use setpanidlist and panrediscover manually.
You MUST build coap node projects with the `COAP_PANID_LIST` predefine to use this functionality.

See `panid_list_example.json` for an example JSON file. Some important notes about this JSON file:
* Each entry key is an EUI addresses, which  can be retrieved from devices via Uniflash.
* EUI address keys MUST be capitalized in the file or they will fail to match.
* spinel-cli.py must be running for the JSON contents to update to the coap node.
* setpanidlistjson must be called each time spine-cli.py is initated on the BR device.
* Intermediate router device are not valid for JSON PAN ID filter lists, as coap nodes only communicate
  with BR devices of the network.

Some details about allow/deny filter list:
* If the allowlist is set, the denylist is ignored. Only when the allowlist is empty is the denylist considered. See the
  rediscovery rules below for the explicit rediscovery decision.
* The current PAN ID filter list on coap devices only has 3 entries for allowlist and 5 entries for denylist.
  Additional entires will be ignored.
* PAN ID filter lists  are not stored in non-volatile memory. They are not preserved on reset.
* The PAN ID filter lists are automatically cleared if the device is unable to join a network after a
  certain timeout period. This timeout value is 30 minutes by default, but can be configured with the `PANID_LIST_TIMEOUT_SEC`.
  parameter in spinel-cli.py

Some further details on the JSON update process
* When a coap node joins the network, it will send a join indication message to the BR with its EUI. The BR will
  scan the JSON file for this EUI.
    * If a matching EUI is found, the BR will send the contents to the joined coap node, which will update its internal PAN ID
      filters with this new info. This does not replace current entries already in the list but instead appends to them.
        * The exception to the append rule is if a new PAN ID entry being added to the allowlist is currently in the
          denylist, or vice versa. To allow the new entry to take precedence, the old entry on the opposite list is
          removed first before adding the new entry.
    * If a match is not found, the BR will assume it knows nothing about the node and does not want it to join. It will
      update the joined coap node with a new denylist entry containing its own PAN ID, triggering a rediscovery.
    * If setpanidlistjson is not called after initializing spinel-cli or the file passed is deleted, the JSON is not
      available. It is assumed direct control via the other panidlist APIs is desired, so the update message to the
      joining coap node will not modify its current PAN ID filters.
* After the update process, the coap node will read its current PAN ID filter lists and decide whether a PAN rediscovery
  (network restart) is needed.
    * If the allowlist is not empty:
        * If the current PAN ID is in the allowlist, then no rediscovery is needed
        * If the current PAN ID is not present, then rediscovery is needed
    * If the allowlist is empty and the denylist is not empty:
        * If the current PAN ID is in the denylist, rediscovery is needed
        * If the current PAN ID is not in the denylist, rediscovery is not needed
    * If both the allowlist and denylist are empty, no rediscovery is needed

```bash
> setpanidlistjson panid_list_example.json
PAN ID list JSON file successfully set

*** On coap node join (no rediscover case) ***
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee: type: 1 (Non-confirmable), token: 444124896, code: 0.02 (Post), msg_id: 11247
CoAP node with address 2020:abcd::212:4b00:14f7:d2ee joined!
Setting coap node PAN ID list according to JSON file
CoAP node EUI found in JSON, sending PAN ID list

CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee: type: 2 (Acknowledgement), token: 17288129104006421587, code: 2.03 (Valid), msg_id: 0
JSON file PAN IDs added to PAN ID list.
PAN rediscovery not required, staying in network

*** On coap node join (rediscover case) ***
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee: type: 1 (Non-confirmable), token: 1044362384, code: 0.02 (Post), msg_id: 25514
CoAP node with address 2020:abcd::212:4b00:14f7:d2ee joined!
Setting coap node PAN ID list according to JSON file
CoAP node EUI found in JSON, sending PAN ID list

CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee: type: 2 (Acknowledgement), token: 12059002529985627774, code: 2.04 (Changed), msg_id: 0
JSON file PAN IDs added to PAN ID list.
PAN rediscovery started
```

#### setpanidlist

Add or remove a PAN ID in the allowlist or denylist for coap nodes.
You MUST build coap node projects with the `COAP_PANID_LIST` predefine to use this functionality.

See setpanidlistjson documentation above for additional details on the allowlist and denylist.

```bash
> setpanidlist 2020:abcd::212:4b00:14f7:d2ee allow add 0xabcd
Sending PAN ID allow/deny list set message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee ...
PAN ID list successfully set

> setpanidlist 2020:abcd::212:4b00:14f7:d2ee allow remove 0xabcd
Sending PAN ID allow/deny list set message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee ...
PAN ID list successfully set

> setpanidlist 2020:abcd::212:4b00:14f7:d2ee deny add 0x1234
Sending PAN ID allow/deny list set message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee ...
PAN ID list successfully set

> setpanidlist 2020:abcd::212:4b00:14f7:d2ee deny remove 0x1234
Sending PAN ID allow/deny list set message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee ...
PAN ID list successfully set
```

#### getpanidlist

Retrieve the contents of the PAN ID allowlist or denylist for coap nodes.
You MUST build coap node projects with the `COAP_PANID_LIST` predefine to use this functionality.

See setpanidlistjson documentation above for additional details on the allowlist and denylist.

```bash
> getpanidlist 2020:abcd::212:4b00:14f7:d2ee allow
Sending PAN ID allow/deny list get message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee: ...
PAN ID list contents:
0xabcd
0x2345

> getpanidlist 2020:abcd::212:4b00:14f7:d2ee deny
Sending PAN ID allow/deny list get message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee: ...
PAN ID list is empty!
```

#### panrediscover

Trigger a PAN rediscover on the specified device by reseting the network stack for coap nodes.
You MUST build coap node projects with the `COAP_PANID_LIST` predefine to use this functionality.

See setpanidlistjson documentation above for additional details on the allowlist and denylist.

```bash
> panrediscover 2020:abcd::212:4b00:14f7:d2ee
Sending PAN rediscover request message
CoAP packet received from 2020:abcd::212:4b00:14f7:d2ee ...
PAN rediscover successfully triggered
```
