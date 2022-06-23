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
asyncchlist      connecteddevices  macfiltermode    q                v
bcchfunction     dodagroute        multicastlist    quit             wisunstack
bcdwellinterval  exit              ncpversion       region
bcinterval       help              networkname      reset
broadcastchlist  history           numconnected     role
ccathreshold     hwaddress         nverase          routerstate
ch0centerfreq    ifconfig          panid            txpower
chspacing        interfacetype     phymodeid        ucchfunction
clear            ipv6addresstable  ping             ucdwellinterval
coap             macfilterlist     protocolversion  unicastchlist
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
