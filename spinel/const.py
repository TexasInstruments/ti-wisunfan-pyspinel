#
#  Copyright (c) 2016-2017, The OpenThread Authors.
#  All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
""" Module-wide constants for spinel package. """


class SPINEL(object):
    """ Singular class that contains all Spinel constants. """
    HEADER_ASYNC = 0x80
    HEADER_DEFAULT = 0x81
    HEADER_EVENT_HANDLER = 0x82

    #=========================================
    # Spinel Commands: Host -> NCP
    #=========================================
    CMD_NOOP = 0
    CMD_RESET = 1
    CMD_PROP_VALUE_GET = 2
    CMD_PROP_VALUE_SET = 3
    CMD_PROP_VALUE_INSERT = 4
    CMD_PROP_VALUE_REMOVE = 5

    #=========================================
    # Spinel Command Responses: NCP -> Host
    #=========================================
    RSP_PROP_VALUE_IS = 6
    RSP_PROP_VALUE_INSERTED = 7
    RSP_PROP_VALUE_REMOVED = 8

    #=========================================
    # Additional Spinel Commands: Host -> NCP
    #=========================================
    CMD_NVERASE = 9

    #=========================================
    # Spinel Command Type
    #=========================================
    ROUTING_TABLE_ENTRY_UNCHANGED = 0
    ROUTING_TABLE_ENTRY_UPDATED = 1
    ROUTING_TABLE_ENTRY_NEW = 2
    ROUTING_TABLE_ENTRY_DELETED = 3
    ROUTING_TABLE_ENTRY_CLEARED = 0xFF

    #=========================================
    # Spinel Properties
    #=========================================

    # Core Properties
    PROP_LAST_STATUS = 0  # < status [i]
    PROP_PROTOCOL_VERSION = 1  # < major, minor [i,i]
    PROP_NCP_VERSION = 2  # < version string [U]
    PROP_INTERFACE_TYPE = 3  # < [i]
    PROP_HWADDR = 8  # < PermEUI64 [E]
    PROP_TRXFWVER = 13  # < PermEUI64 [E]

    # PHY Properties
    PROP_PHY__BEGIN = 0x20
    PROP_PHY_CCA_THRESHOLD = PROP_PHY__BEGIN + 4  # < dBm [c]
    PROP_PHY_TX_POWER = PROP_PHY__BEGIN + 5  # < [c]
    PROP_PHY_NUM_NBRS = PROP_PHY__BEGIN + 6  # < dBm [c]
    PROP_PHY_NBR_METRICS = PROP_PHY__BEGIN + 7  # < dBm [c]
    PROP_PHY__END = 0x30

    PROP_PHY_EXT__BEGIN = 0x1200
    PROP_PHY_EXT__END = 0x1300

    # MAC Properties
    PROP_MAC__BEGIN = 0x30
    PROP_MAC_15_4_PANID = PROP_MAC__BEGIN + 6  # < [S]
    PROP_MAC__END = 0x40

    PROP_MAC_EXT__BEGIN = 0x1300
    PROP_MAC_EXT__END = 0x1400

    # NET Properties
    PROP_NET__BEGIN = 0x40
    PROP_NET_IF_UP = PROP_NET__BEGIN + 1  # < [b]
    PROP_NET_STACK_UP = PROP_NET__BEGIN + 2  # < [C]
    PROP_NET_ROLE = PROP_NET__BEGIN + 3  # < [C]
    PROP_NET_NETWORK_NAME = PROP_NET__BEGIN + 4  # < [U]
    PROP_NET__END = 0x50

    PROP_NET_EXT__BEGIN = 0x1400
    PROP_NET_EXT__END = 0x1500

    # Wi-SUN (Tech Specific) Properties
    PROP_WISUN__BEGIN = 0x50
    PROP_PHY_REGION = PROP_WISUN__BEGIN + 0 # < [C]
    PROP_PHY_MODE_ID = PROP_WISUN__BEGIN + 1 # < [C]
    PROP_PHY_UNICAST_CHANNEL_LIST = PROP_WISUN__BEGIN + 2 # < [D]
    PROP_PHY_BROADCAST_CHANNEL_LIST = PROP_WISUN__BEGIN + 3 # < [D]
    PROP_PHY_ASYNC_CHANNEL_LIST = PROP_WISUN__BEGIN + 4 # < [D]
    PROP_NET_STATE = PROP_WISUN__BEGIN + 11
    PROP_PARENT_LIST = PROP_WISUN__BEGIN + 12
    PROP_ROUTING_COST = PROP_WISUN__BEGIN + 13
    PROP_ROUTING_TABLE_UPDATE = PROP_WISUN__BEGIN + 14
    PROP_DODAG_ROUTE_DEST = PROP_WISUN__BEGIN + 15
    PROP_DODAG_ROUTE = PROP_WISUN__BEGIN + 16
    PROP_WISUN__END = 0x60

    PROP_WISUN_EXT__BEGIN = 0x1500
    PROP_PHY_CH_SPACING = PROP_WISUN_EXT__BEGIN + 0 # < [S]
    PROP_PHY_CHO_CENTER_FREQ = PROP_WISUN_EXT__BEGIN + 1 # < Ch0-MHz, Ch0-KHz [t(SS)]
    PROP_MAC_UC_DWELL_INTERVAL = PROP_WISUN_EXT__BEGIN + 86 # < [C]
    PROP_MAC_BC_DWELL_INTERVAL = PROP_WISUN_EXT__BEGIN + 87 # < [C]
    PROP_MAC_BC_INTERVAL = PROP_WISUN_EXT__BEGIN + 88 # < [L]
    PROP_MAC_UC_CHANNEL_FUNCTION = PROP_WISUN_EXT__BEGIN + 89 # < [C]
    PROP_MAC_BC_CHANNEL_FUNCTION = PROP_WISUN_EXT__BEGIN + 90 # < [C]
    PROP_MAC_MAC_FILTER_LIST = PROP_WISUN_EXT__BEGIN + 91 # < [A(E)]
    PROP_MAC_FILTER_MODE = PROP_WISUN_EXT__BEGIN + 92   # < [C]
    PROP_TEST_COMMAND = PROP_WISUN_EXT__BEGIN + 93   # < [b]
    #TI WI-SUN NET
    PROP_REVOKE_GTK_HWADDR = PROP_WISUN_EXT__BEGIN + 171   # < [C]
    PROP_WISUN_EXT__END = 0x1600

    # IPV6 Properties
    PROP_IPV6__BEGIN = 0x60
    # < array(ipv6addr,prefixlen,valid,preferred,flags) [A(t(6CLLC))]
    PROP_IPV6_ADDRESS_TABLE = PROP_IPV6__BEGIN + 3
    PROP_MULTICAST_LIST = PROP_IPV6__BEGIN + 4
    PROP_NUM_CONNECTED_DEVICES = PROP_IPV6__BEGIN + 5
    PROP_CONNECTED_DEVICES = PROP_IPV6__BEGIN + 6
    PROP_IPV6__BEGIN = 0x70
    PROP_IPV6_EXT__BEGIN = 0x1600
    PROP_IPV6_EXT__END = 0x1700

    # STREAM Properties
    PROP_STREAM__BEGIN = 0x70
    PROP_STREAM_NET = PROP_STREAM__BEGIN + 2  # < [D]
    PROP_STREAM__END = 0x80

    PROP_STREAM_EXT__BEGIN = 0x1700
    PROP_STREAM_EXT__END = 0x1800


class kThread(object):
    """ OpenThread constant class. """
    PrefixPreferenceOffset = 6
    PrefixPreferredFlag = 1 << 5
    PrefixSlaacFlag = 1 << 4
    PrefixDhcpFlag = 1 << 3
    PrefixConfigureFlag = 1 << 2
    PrefixDefaultRouteFlag = 1 << 1
    PrefixOnMeshFlag = 1 << 0


#=========================================

SPINEL_LAST_STATUS_MAP = {
    0:
        "STATUS_OK: Operation has completed successfully.",
    1:
        "STATUS_FAILURE: Operation has failed for some undefined reason.",
    2:
        "STATUS_UNIMPLEMENTED: The given operation has not been implemented.",
    3:
        "STATUS_INVALID_ARGUMENT: An argument to the given operation is invalid.",
    4:
        "STATUS_INVALID_STATE : The given operation is invalid for the current state of the device.",
    5:
        "STATUS_INVALID_COMMAND: The given command is not recognized.",
    6:
        "STATUS_INVALID_INTERFACE: The given Spinel interface is not supported.",
    7:
        "STATUS_INTERNAL_ERROR: An internal runtime error has occured.",
    8:
        "STATUS_SECURITY_ERROR: A security or authentication error has occured.",
    9:
        "STATUS_PARSE_ERROR: An error has occured while parsing the command.",
    10:
        "STATUS_IN_PROGRESS: The operation is in progress and will be completed asynchronously.",
    11:
        "STATUS_NOMEM: The operation has been prevented due to memory pressure.",
    12:
        "STATUS_BUSY: The device is currently performing a mutually exclusive operation.",
    13:
        "STATUS_PROPERTY_NOT_FOUND: The given property is not recognized.",
    14:
        "STATUS_PACKET_DROPPED: The packet was dropped.",
    15:
        "STATUS_EMPTY: The result of the operation is empty.",
    16:
        "STATUS_CMD_TOO_BIG: The command was too large to fit in the internal buffer.",
    17:
        "STATUS_NO_ACK: The packet was not acknowledged.",
    18:
        "STATUS_CCA_FAILURE: The packet was not sent due to a CCA failure.",
    19:
        "STATUS_ALREADY: The operation is already in progress.",
    20:
        "STATUS_ITEM_NOT_FOUND: The given item could not be found.",
    21:
        "STATUS_INVALID_COMMAND_FOR_PROP: The given command cannot be performed on this property.",
    23:
        "STATUS_NO_PEERS: There no peers with matching network name.",
    24:
        "STATUS_NO_NEIGHBORTABLE_ENTRY: There is neighbor table entry, Packet failed to transmit.",
    25:
        "STATUS_AUTHENTICATION_FAILURE: Certificates did not match up.",
    26:
        "STATUS_KEY_EXCHANGE_FAILED : Certificates are good but key exchanged failed due to timeout. Device will automatically try to reconnect to server.",
    27:
        "STATUS_DHCPV6_ADDRESS_ASSIGNMENT_FAILED : Device was unable to get a GUA from DHCPv6 Server.",
    28:
        "STATUS_NET_JOIN_FAILED : Device was unable to join network due to other issues. "

}
