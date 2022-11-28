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
"""
Module providing a Spienl coder / decoder class.
"""

import binascii
import time
import logging
import threading
import traceback
import queue
import importlib

from struct import pack
from struct import unpack
from collections import namedtuple
from collections import defaultdict

import ipaddress

import spinel.util as util
import spinel.config as CONFIG
from spinel.const import kThread
from spinel.const import SPINEL
from spinel.const import SPINEL_LAST_STATUS_MAP
from spinel.hdlc import Hdlc

FEATURE_USE_HDLC = 1

TIMEOUT_PROP = 5

#=========================================
#   SpinelCodec
#=========================================

#  0: DATATYPE_NULL
#'.': DATATYPE_VOID: Empty data type. Used internally.
#'b': DATATYPE_BOOL: Boolean value. Encoded in 8-bits as either 0x00 or 0x01.
#                    All other values are illegal.
#'C': DATATYPE_UINT8: Unsigned 8-bit integer.
#'c': DATATYPE_INT8: Signed 8-bit integer.
#'S': DATATYPE_UINT16: Unsigned 16-bit integer. (Little-endian)
#'s': DATATYPE_INT16: Signed 16-bit integer. (Little-endian)
#'L': DATATYPE_UINT32: Unsigned 32-bit integer. (Little-endian)
#'l': DATATYPE_INT32: Signed 32-bit integer. (Little-endian)
#'i': DATATYPE_UINT_PACKED: Packed Unsigned Integer. (See section 7.2)
#'6': DATATYPE_IPv6ADDR: IPv6 Address. (Big-endian)
#'E': DATATYPE_EUI64: EUI-64 Address. (Big-endian)
#'e': DATATYPE_EUI48: EUI-48 Address. (Big-endian)
#'D': DATATYPE_DATA: Arbitrary Data. (See section 7.3)
#'d': DATATYPE_DATA_WLEN: Arbitrary Data with Prepended Length. (See section 7.3)
#'U': DATATYPE_UTF8: Zero-terminated UTF8-encoded string.
#'t': DATATYPE_STRUCT: Structured datatype. Compound type. Length prepended. (See section 7.4)
#'A': DATATYPE_ARRAY: Array of datatypes. Compound type. (See section 7.5)


class SpinelCodec(object):
    """ A general coder / decoder class for Spinel protocol. """

    @classmethod
    def parse_b(cls, payload):
        return unpack("<B", payload[:1])[0]

    @classmethod
    def parse_c(cls, payload):
        return unpack("<b", payload[:1])[0]

    @classmethod
    def parse_C(cls, payload):
        return unpack("<B", payload[:1])[0]

    @classmethod
    def parse_s(cls, payload):
        return unpack("<h", payload[:2])[0]

    @classmethod
    def parse_S(cls, payload):
        return unpack("<H", payload[:2])[0]

    @classmethod
    def parse_l(cls, payload):
        return unpack("<l", payload[:4])[0]

    @classmethod
    def parse_L(cls, payload):
        return unpack("<L", payload[:4])[0]

    @classmethod
    def parse_X(cls, payload):
        return unpack("<Q", payload[:8])[0]

    @classmethod
    def parse_6(cls, payload):
        return payload[:16]

    @classmethod
    def parse_E(cls, payload):
        return payload[:8]

    @classmethod
    def parse_e(cls, payload):
        return payload[:6]

    @classmethod
    def parse_U(cls, payload):
        payload = payload.decode('utf-8')
        nullchar = '\0'

        if payload.find(nullchar) >= 0:
            return payload[:payload.index(nullchar)]  # strip null
        else:
            return payload

    @classmethod
    def parse_D(cls, payload):
        return payload

    @classmethod
    def parse_d(cls, payload):
        return payload[2:2 + unpack("<H", payload[:2])[0]]

    @classmethod
    def parse_i(cls, payload):
        """ Decode EXI integer format. """
        value = 0
        value_len = 0
        value_mul = 1

        while value_len < 4:
            byte = payload[value_len]

            value += (byte & 0x7F) * value_mul
            if byte < 0x80:
                break
            value_mul *= 0x80
            value_len += 1

        return (value, value_len + 1)

    @classmethod
    def parse_i_len(cls, payload):
        """ Decode length of EXI integer format. """
        return cls.parse_i(payload)[1]

    @classmethod
    def index_of_ending_brace(cls, spinel_format, idx):
        """ Determines the index of the matching closing brace. """
        count = 1
        orig_idx = idx
        while count > 0 and idx < len(spinel_format) - 1:
            idx += 1
            if spinel_format[idx] == ')':
                count -= 1
            elif spinel_format[idx] == '(':
                count += 1
        if count != 0:
            raise ValueError('Unbalanced parenthesis in format string "' +
                             spinel_format + '", idx=' + idx)
        return idx

    @classmethod
    def parse_field(cls, payload, spinel_format):
        map_decode = {
            'b': cls.parse_b,
            'c': cls.parse_c,
            'C': cls.parse_C,
            's': cls.parse_s,
            'S': cls.parse_S,
            'L': cls.parse_L,
            'l': cls.parse_l,
            '6': cls.parse_6,
            'X': cls.parse_X,
            'E': cls.parse_E,
            'e': cls.parse_e,
            'U': cls.parse_U,
            'D': cls.parse_D,
            'd': cls.parse_d,
            'i': cls.parse_i,
        }
        try:
            return map_decode[spinel_format[0]](payload)
        except KeyError:
            print(traceback.format_exc())
            return None

    @classmethod
    def get_payload_size(cls, payload, spinel_format):
        map_lengths = {
            'b': 1,
            'c': 1,
            'C': 1,
            's': 2,
            'S': 2,
            'l': 4,
            'L': 4,
            '6': 16,
            'X': 8,
            'E': 8,
            'e': 6,
        }

        result = 0

        idx = 0
        while idx < len(spinel_format):
            format = spinel_format[idx]

            if format == 't':
                if spinel_format[idx + 1] != '(':
                    raise ValueError('Invalid structure format')

                struct_end = cls.index_of_ending_brace(spinel_format, idx + 1)

                result += 2 + cls.parse_S(payload[result:])
                idx = struct_end + 1

            elif format == 'd':
                result += 2 + cls.parse_S(payload[result:])
                idx += 1

            elif format == 'D' or format == 'A':
                if idx != len(spinel_format) - 1:
                    raise ValueError('Invalid type syntax for "' + format +
                                     '", must go at end of format string')
                result = len(payload)
                idx += 1

            elif format == 'U':
                result += payload[result:].index(0) + 1
                idx += 1

            elif format == 'i':
                result += cls.parse_i_len(payload[result:])
                idx += 1

            else:
                result += map_lengths[format]
                idx += 1

        return result

    @classmethod
    def parse_fields(cls, payload, spinel_format):
        result = []

        idx = 0
        while idx < len(spinel_format):
            format = spinel_format[idx]

            if format == 'A':
                if spinel_format[idx + 1] != '(':
                    raise ValueError('Invalid structure format')

                array_end = cls.index_of_ending_brace(spinel_format, idx + 1)

                array_format = spinel_format[idx + 2:array_end]

                array = []
                while len(payload):
                    array.append(cls.parse_fields(payload, array_format))
                    payload = payload[cls.
                                      get_payload_size(payload, array_format):]

                result.append(tuple(array))
                idx = array_end + 1

            elif format == 't':
                if spinel_format[idx + 1] != '(':
                    raise ValueError('Invalid structure format')

                struct_end = cls.index_of_ending_brace(spinel_format, idx + 1)

                struct_format = spinel_format[idx + 2:struct_end]
                struct_len = cls.parse_S(payload)

                result.append(
                    cls.parse_fields(payload[2:struct_len + 2], struct_format))
                payload = payload[struct_len + 2:]

                idx = struct_end + 1

            else:
                result.append(cls.parse_field(payload, format))
                payload = payload[cls.get_payload_size(payload, format):]

                idx += 1

        return tuple(result)

    @classmethod
    def encode_i(cls, data):
        """ Encode EXI integer format. """
        result = bytes()
        while data:
            value = data & 0x7F
            data >>= 7
            if data:
                value |= 0x80
            result = result + pack("<B", value)
        return result

    @classmethod
    def encode_b(cls, value):
        return pack('B', value)

    @classmethod
    def encode_c(cls, value):
        return pack('B', value)

    @classmethod
    def encode_C(cls, value):
        return pack('B', value)

    @classmethod
    def encode_s(cls, value):
        return pack('<h', value)

    @classmethod
    def encode_S(cls, value):
        return pack('<H', value)

    @classmethod
    def encode_l(cls, value):
        return pack('<l', value)

    @classmethod
    def encode_L(cls, value):
        return pack('<L', value)

    @classmethod
    def encode_6(cls, value):
        return value[:16]

    @classmethod
    def encode_E(cls, value):
        return value[:8]

    @classmethod
    def encode_e(cls, value):
        return value[:6]

    @classmethod
    def encode_U(cls, value):
        return value + '\0'

    @classmethod
    def encode_D(cls, value):
        return value

    @classmethod
    def encode_d(cls, value):
        return cls.encode_S(len(value)) + value

    @classmethod
    def encode_field(cls, code, value):
        map_encode = {
            'b': cls.encode_b,
            'c': cls.encode_c,
            'C': cls.encode_C,
            's': cls.encode_s,
            'S': cls.encode_S,
            'L': cls.encode_L,
            'l': cls.encode_l,
            '6': cls.encode_6,
            'E': cls.encode_E,
            'e': cls.encode_e,
            'U': cls.encode_U,
            'D': cls.encode_D,
            'd': cls.encode_d,
            'i': cls.encode_i,
        }
        try:
            return map_encode[code](value)
        except KeyError:
            print(traceback.format_exc())
            return None

    def next_code(self, spinel_format):
        code = spinel_format[0]
        spinel_format = spinel_format[1:]
        # TODO: Handle T() and A()
        return code, spinel_format

    def encode_fields(self, spinel_format, *fields):
        packed = bytes()
        for field in fields:
            code, spinel_format = self.next_code(spinel_format)
            if not code:
                break
            packed += self.encode_field(code, field)
        return packed

    def encode_packet(self,
                      command_id,
                      payload=bytes(),
                      tid=SPINEL.HEADER_DEFAULT):
        """ Encode the given payload as a Spinel frame. """
        header = pack(">B", tid)
        cmd = self.encode_i(command_id)
        pkt = header + cmd + payload
        return pkt


#=========================================


class SpinelPropertyHandler(SpinelCodec):

    def LAST_STATUS(self, _, payload):
        return self.parse_i(payload)[0]

    def PROTOCOL_VERSION(self, _wpan_api, payload):
        return self.parse_U(payload)

    def NCP_VERSION(self, _, payload):
        return self.parse_U(payload)

    def INTERFACE_TYPE(self, _, payload):
        return self.parse_i(payload)[0]

    def HWADDR(self, _, payload):
        return self.parse_E(payload)

    def TRXFWVER(self, _, payload):
        return self.parse_D(payload)

    def PHY_CCA_THRESHOLD(self, _, payload):
        return self.parse_c(payload)

    def PHY_TX_POWER(self, _, payload):
        return self.parse_c(payload)

    def PHY_NUM_NBRS(self, _, payload):
        return self.parse_c(payload)

    def PHY_NBR_METRICS(self, _, payload):
        return self.parse_D(payload)

    def MAC_15_4_PANID(self, _, payload):
        return self.parse_S(payload)

    def NET_IF_UP(self, _, payload):
        return self.parse_b(payload)

    def NET_STACK_UP(self, _, payload):
        return self.parse_C(payload)

    def NET_ROLE(self, _, payload):
        return self.parse_C(payload)

    def NET_NETWORK_NAME(self, _, payload):
        return self.parse_U(payload)

    def PROP_PHY_REGION(self, _, payload):
        return self.parse_C(payload)

    def PROP_PHY_MODE_ID(self, _, payload):
        return self.parse_C(payload)

    def PROP_PHY_UNICAST_CHANNEL_LIST(self, _, payload):
        return self.parse_D(payload)

    def PROP_PHY_BROADCAST_CHANNEL_LIST(self, _, payload):
        return self.parse_D(payload)

    def PROP_PHY_ASYNC_CHANNEL_LIST(self, _, payload):
        return self.parse_D(payload)

    def PROP_NET_STATE(self, _, payload):
        return self.parse_C(payload)

    def PROP_PARENT_LIST(self, _, payload):
        return self.parse_D(payload)

    def PROP_ROUTING_COST(self, _, payload):
        return self.parse_C(payload)

    def PROP_ROUTING_TABLE_UPDATE(self, _, payload):
        return self.parse_D(payload)

    def PROP_DODAG_ROUTE(self, _, payload):
        return self.parse_D(payload)

    def PROP_PHY_CH_SPACING(self, _, payload):
        return self.parse_D(payload)

    def PROP_PHY_CHO_CENTER_FREQ(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_UC_DWELL_INTERVAL(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_BC_DWELL_INTERVAL(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_BC_INTERVAL(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_UC_CHANNEL_FUNCTION(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_BC_CHANNEL_FUNCTION(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_MAC_FILTER_LIST(self, _, payload):
        return self.parse_D(payload)

    def PROP_MAC_FILTER_MODE(self, _, payload):
        return self.parse_C(payload)

    def PROP_TEST_COMMAND(self, _, payload):
        return self.parse_b(payload)

    def PROP_REVOKE_GTK_HWADDR(self, _, payload):
        return self.parse_E(payload)

    def __init__(self):
        self.autoAddresses = set()

        self.wpan_api = None
        self.__queue_prefix = queue.Queue()
        self.prefix_thread = threading.Thread(target=self.__run_prefix_handler)
        self.prefix_thread.setDaemon(True)
        self.prefix_thread.start()

    def handle_prefix_change(self, payload):
        """ Automatically ipaddr add / remove addresses for each new prefix. """
        # As done by cli.cpp Interpreter::HandleNetifStateChanged

        # First parse payload and extract slaac prefix information.
        pay = payload
        Prefix = namedtuple("Prefix", "prefix prefixlen stable flags is_local")
        prefixes = []
        slaacPrefixSet = set()
        while len(pay) >= 22:
            (_structlen) = unpack('<H', pay[:2])
            struct_len = _structlen[0]
            pay = pay[2:]
            prefix = Prefix(*unpack('16sBBBB', pay[:20]))
            if prefix.flags & kThread.PrefixSlaacFlag:
                net6 = ipaddress.IPv6Network(prefix.prefix)
                net6 = net6.supernet(new_prefix=prefix.prefixlen)
                slaacPrefixSet.add(net6)
                prefixes.append(prefix)
            pay = pay[struct_len:]

        if CONFIG.DEBUG_LOG_PROP:
            print("\n========= PREFIX ============")
            print("ipaddrs: " + str(self.autoAddresses))
            print("slaac prefix set: " + str(slaacPrefixSet))
            print("==============================\n")

    def __run_prefix_handler(self):
        while 1:
            (wpan_api, payload) = self.__queue_prefix.get(True)
            self.wpan_api = wpan_api
            self.handle_prefix_change(payload)
            self.__queue_prefix.task_done()

    def DODAG_ROUTE_DEST(self, _, payload):
        return self.parse_D(payload)

    def DODAG_ROUTE(self, _, payload):
        return self.parse_D(payload)

    def NUM_CONNECTED_DEVICES(self, _, payload):
        return self.parse_S(payload)

    def CONNECTED_DEVICES(self, _, payload):
        return self.parse_D(payload)

    def IPV6_ADDRESS_TABLE(self, _, payload):
        return self.parse_D(payload)

    def MULTICAST_LIST(self, _, payload):
        return self.parse_D(payload)

    def STREAM_NET(self, _, payload):
        return self.parse_d(payload)



#=========================================


class SpinelCommandHandler(SpinelCodec):

    def handle_prop(self, wpan_api, name, payload, tid):
        (prop_id, prop_len) = self.parse_i(payload)

        if prop_id in SPINEL_PROP_DISPATCH:
            handler = SPINEL_PROP_DISPATCH[prop_id]
            prop_name = handler.__name__

            prop_value = handler(wpan_api, payload[prop_len:])

            if CONFIG.DEBUG_LOG_PROP:

                # Generic output
                if isinstance(prop_value, str):
                    prop_value_str = util.hexify_str(prop_value)
                    CONFIG.LOGGER.debug("PROP_VALUE_%s [tid=%d]: %s = %s", name,
                                        (tid & 0xF), prop_name, prop_value_str)
                else:
                    prop_value_str = str(prop_value)

                    CONFIG.LOGGER.debug("PROP_VALUE_%s [tid=%d]: %s = %s", name,
                                        (tid & 0xF), prop_name, prop_value_str)

                # Extend output for certain properties.
                if prop_id == SPINEL.PROP_LAST_STATUS:
                    CONFIG.LOGGER.debug(SPINEL_LAST_STATUS_MAP[prop_value])

            if CONFIG.DEBUG_LOG_PKT:
                if ((prop_id == SPINEL.PROP_STREAM_NET) or
                    (prop_id == SPINEL.PROP_STREAM_NET_INSECURE)):
                    CONFIG.LOGGER.debug("PROP_VALUE_" + name + ": " + prop_name)

                elif prop_id == SPINEL.PROP_STREAM_DEBUG:
                    CONFIG.LOGGER.debug("DEBUG: " + prop_value)

            if wpan_api:
                wpan_api.queue_add(prop_id, prop_value, tid)
            else:
                print("no wpan_api")
        elif CONFIG.DEBUG_LOG_PROP:
            prop_name = "Property Unknown"
            CONFIG.LOGGER.info("\n%s (%i): ", prop_name, prop_id)

    def PROP_VALUE_IS(self, wpan_api, payload, tid):
        self.handle_prop(wpan_api, "IS", payload, tid)

    def PROP_VALUE_INSERTED(self, wpan_api, payload, tid):
        self.handle_prop(wpan_api, "INSERTED", payload, tid)

    def PROP_VALUE_REMOVED(self, wpan_api, payload, tid):
        self.handle_prop(wpan_api, "REMOVED", payload, tid)


WPAN_CMD_HANDLER = SpinelCommandHandler()

SPINEL_COMMAND_DISPATCH = {
    SPINEL.RSP_PROP_VALUE_IS: WPAN_CMD_HANDLER.PROP_VALUE_IS,
    SPINEL.RSP_PROP_VALUE_INSERTED: WPAN_CMD_HANDLER.PROP_VALUE_INSERTED,
    SPINEL.RSP_PROP_VALUE_REMOVED: WPAN_CMD_HANDLER.PROP_VALUE_REMOVED,
}

WPAN_PROP_HANDLER = SpinelPropertyHandler()

SPINEL_PROP_DISPATCH = {
    SPINEL.PROP_LAST_STATUS:
        WPAN_PROP_HANDLER.LAST_STATUS,
    SPINEL.PROP_PROTOCOL_VERSION:
        WPAN_PROP_HANDLER.PROTOCOL_VERSION,
    SPINEL.PROP_NCP_VERSION:
        WPAN_PROP_HANDLER.NCP_VERSION,
    SPINEL.PROP_INTERFACE_TYPE:
        WPAN_PROP_HANDLER.INTERFACE_TYPE,
    SPINEL.PROP_HWADDR:
        WPAN_PROP_HANDLER.HWADDR,
    SPINEL.PROP_TRXFWVER:
        WPAN_PROP_HANDLER.TRXFWVER,
    SPINEL.PROP_PHY_CCA_THRESHOLD:
        WPAN_PROP_HANDLER.PHY_CCA_THRESHOLD,
    SPINEL.PROP_PHY_TX_POWER:
        WPAN_PROP_HANDLER.PHY_TX_POWER,
    SPINEL.PROP_PHY_NUM_NBRS:
        WPAN_PROP_HANDLER.PHY_NUM_NBRS,
    SPINEL.PROP_PHY_NBR_METRICS:
        WPAN_PROP_HANDLER.PHY_NBR_METRICS,
    SPINEL.PROP_MAC_15_4_PANID:
        WPAN_PROP_HANDLER.MAC_15_4_PANID,
    SPINEL.PROP_NET_IF_UP:
        WPAN_PROP_HANDLER.NET_IF_UP,
    SPINEL.PROP_NET_STACK_UP:
        WPAN_PROP_HANDLER.NET_STACK_UP,
    SPINEL.PROP_NET_ROLE:
        WPAN_PROP_HANDLER.NET_ROLE,
    SPINEL.PROP_NET_NETWORK_NAME:
        WPAN_PROP_HANDLER.NET_NETWORK_NAME,
    SPINEL.PROP_PHY_REGION:
        WPAN_PROP_HANDLER.PROP_PHY_REGION,
    SPINEL.PROP_PHY_MODE_ID:
        WPAN_PROP_HANDLER.PROP_PHY_MODE_ID,
    SPINEL.PROP_PHY_UNICAST_CHANNEL_LIST:
        WPAN_PROP_HANDLER.PROP_PHY_UNICAST_CHANNEL_LIST,
    SPINEL.PROP_PHY_BROADCAST_CHANNEL_LIST:
        WPAN_PROP_HANDLER.PROP_PHY_BROADCAST_CHANNEL_LIST,
    SPINEL.PROP_PHY_ASYNC_CHANNEL_LIST:
        WPAN_PROP_HANDLER.PROP_PHY_ASYNC_CHANNEL_LIST,
    SPINEL.PROP_NET_STATE:
        WPAN_PROP_HANDLER.PROP_NET_STATE,
    SPINEL.PROP_PARENT_LIST:
        WPAN_PROP_HANDLER.PROP_PARENT_LIST,
    SPINEL.PROP_ROUTING_COST:
        WPAN_PROP_HANDLER.PROP_ROUTING_COST,
    SPINEL.PROP_ROUTING_TABLE_UPDATE:
        WPAN_PROP_HANDLER.PROP_ROUTING_TABLE_UPDATE,
    SPINEL.PROP_DODAG_ROUTE:
        WPAN_PROP_HANDLER.PROP_DODAG_ROUTE,
    SPINEL.PROP_PHY_CH_SPACING:
        WPAN_PROP_HANDLER.PROP_PHY_CH_SPACING,
    SPINEL.PROP_PHY_CHO_CENTER_FREQ:
        WPAN_PROP_HANDLER.PROP_PHY_CHO_CENTER_FREQ,
    SPINEL.PROP_MAC_UC_DWELL_INTERVAL:
        WPAN_PROP_HANDLER.PROP_MAC_UC_DWELL_INTERVAL,
    SPINEL.PROP_MAC_BC_DWELL_INTERVAL:
        WPAN_PROP_HANDLER.PROP_MAC_BC_DWELL_INTERVAL,
    SPINEL.PROP_MAC_BC_INTERVAL:
        WPAN_PROP_HANDLER.PROP_MAC_BC_INTERVAL,
    SPINEL.PROP_MAC_UC_CHANNEL_FUNCTION:
        WPAN_PROP_HANDLER.PROP_MAC_UC_CHANNEL_FUNCTION,
    SPINEL.PROP_MAC_BC_CHANNEL_FUNCTION:
        WPAN_PROP_HANDLER.PROP_MAC_BC_CHANNEL_FUNCTION,
    SPINEL.PROP_MAC_MAC_FILTER_LIST:
        WPAN_PROP_HANDLER.PROP_MAC_MAC_FILTER_LIST,
    SPINEL.PROP_MAC_FILTER_MODE:
        WPAN_PROP_HANDLER.PROP_MAC_FILTER_MODE,
    SPINEL.PROP_TEST_COMMAND:
        WPAN_PROP_HANDLER.PROP_TEST_COMMAND,
    SPINEL.PROP_DODAG_ROUTE_DEST:
        WPAN_PROP_HANDLER.DODAG_ROUTE_DEST,
    SPINEL.PROP_DODAG_ROUTE:
        WPAN_PROP_HANDLER.DODAG_ROUTE,
    SPINEL.PROP_NUM_CONNECTED_DEVICES:
        WPAN_PROP_HANDLER.NUM_CONNECTED_DEVICES,
    SPINEL.PROP_CONNECTED_DEVICES:
        WPAN_PROP_HANDLER.CONNECTED_DEVICES,
    SPINEL.PROP_REVOKE_GTK_HWADDR:
        WPAN_PROP_HANDLER.PROP_REVOKE_GTK_HWADDR,
    SPINEL.PROP_IPV6_ADDRESS_TABLE:
        WPAN_PROP_HANDLER.IPV6_ADDRESS_TABLE,
    SPINEL.PROP_MULTICAST_LIST:
        WPAN_PROP_HANDLER.MULTICAST_LIST,
    SPINEL.PROP_STREAM_NET:
        WPAN_PROP_HANDLER.STREAM_NET,
}


class WpanApi(SpinelCodec):
    """ Helper class to format wpan command packets """

    def __init__(self,
                 stream,
                 nodeid,
                 use_hdlc=FEATURE_USE_HDLC,
                 timeout=TIMEOUT_PROP,
                 vendor_module=None):
        self.stream = stream
        self.nodeid = nodeid

        self.timeout = timeout

        self.use_hdlc = use_hdlc
        if self.use_hdlc:
            self.hdlc = Hdlc(self.stream)

        if vendor_module:
            # Hook vendor properties
            try:
                codec = importlib.import_module(vendor_module + '.codec')
                SPINEL_PROP_DISPATCH.update(codec.VENDOR_SPINEL_PROP_DISPATCH)
            except ImportError:
                pass

        # PARSER state
        self.rx_pkt = []
        self.callback = defaultdict(list)  # Map prop_id to list of callbacks.

        # Fire up threads
        self._reader_alive = True
        self.tid_filter = set()
        self.__queue_prop = defaultdict(queue.Queue)  # Map tid to Queue.
        self.queue_register()
        self.__start_reader()

    def __del__(self):
        self._reader_alive = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._reader_alive = False

    def __start_reader(self):
        """Start reader thread"""
        self._reader_alive = True
        # start serial->console thread
        self.receiver_thread = threading.Thread(target=self.stream_rx)
        self.receiver_thread.setDaemon(True)
        self.receiver_thread.start()

    def transact(self, command_id, payload=bytes(), tid=SPINEL.HEADER_DEFAULT):
        pkt = self.encode_packet(command_id, payload, tid)
        if CONFIG.DEBUG_LOG_SERIAL:
            msg = "TX Pay: (%i) %s " % (len(pkt),
                                        binascii.hexlify(pkt).decode('utf-8'))
            CONFIG.LOGGER.debug(msg)

        if self.use_hdlc:
            pkt = self.hdlc.encode(pkt)
        self.stream_tx(pkt)

    def parse_rx(self, pkt):
        if not pkt:
            return

        if CONFIG.DEBUG_LOG_SERIAL:
            msg = "RX Pay: (%i) %s " % (len(pkt),
                                        binascii.hexlify(pkt).decode('utf-8'))
            CONFIG.LOGGER.debug(msg)

        length = len(pkt) - 2
        if length < 0:
            return

        spkt = pkt

        #if not isinstance(spkt, str):
        #    spkt = "".join(map(chr, spkt))

        tid = self.parse_C(spkt[:1])
        (cmd_id, cmd_length) = self.parse_i(spkt[1:])
        pay_start = cmd_length + 1
        payload = spkt[pay_start:]

        try:
            handler = SPINEL_COMMAND_DISPATCH[cmd_id]
            cmd_name = handler.__name__
            handler(self, payload, tid)

        except Exception as _ex:
            print(traceback.format_exc())
            cmd_name = "CB_Unknown"
            CONFIG.LOGGER.info("\n%s (%i): ", cmd_name, cmd_id)

        if CONFIG.DEBUG_CMD_RESPONSE:
            CONFIG.LOGGER.info("\n%s (%i): ", cmd_name, cmd_id)
            CONFIG.LOGGER.info("===> %s",
                               binascii.hexlify(payload).decode('utf-8'))

    def stream_tx(self, pkt):
        # Encapsulate lagging and Framer support in self.stream class.
        self.stream.write(pkt)

    def stream_rx(self):
        """ Recieve thread and parser. """
        try:
            while self._reader_alive:
                if self.use_hdlc:
                    self.rx_pkt = self.hdlc.collect()
                else:
                    # size=None: Assume stream will always deliver packets
                    pkt = self.stream.read(None)
                    self.rx_pkt = util.packed_to_array(pkt)

                self.parse_rx(self.rx_pkt)
        except:
            if self._reader_alive:
                raise
            else:
                # Ignore the error since we are exiting
                pass

    class PropertyItem(object):
        """ Queue item for NCP response to property commands. """

        def __init__(self, prop, value, tid):
            self.prop = prop
            self.value = value
            self.tid = tid

    def callback_register(self, prop, cb):
        self.callback[prop].append(cb)

    def queue_register(self, tid=SPINEL.HEADER_DEFAULT):
        self.tid_filter.add(tid)
        return self.__queue_prop[tid]

    def queue_wait_prepare(self, _prop_id, tid=SPINEL.HEADER_DEFAULT):
        self.queue_clear(tid)

    def queue_add(self, prop, value, tid):
        cb_list = self.callback[prop]

        # Asynchronous handlers can consume message and not add to queue.
        if len(cb_list) > 0:
            consumed = cb_list[0](prop, value, tid)
            if consumed:
                return

        if tid not in self.tid_filter:
            return
        item = self.PropertyItem(prop, value, tid)
        self.__queue_prop[tid].put_nowait(item)

    def queue_clear(self, tid):
        with self.__queue_prop[tid].mutex:
            self.__queue_prop[tid].queue.clear()

    def queue_get(self, tid, timeout=None):
        try:
            if (timeout):
                item = self.__queue_prop[tid].get(True, timeout)
            else:
                item = self.__queue_prop[tid].get_nowait()
        except queue.Empty:
            item = None
        return item

    def queue_wait_for_prop(self,
                            _prop,
                            tid=SPINEL.HEADER_DEFAULT,
                            timeout=None):
        if _prop is None:
            return None

        if timeout is None:
            timeout = self.timeout

        processed_queue = queue.Queue()
        timeout_time = time.time() + timeout

        while time.time() < timeout_time:
            item = self.queue_get(tid, timeout_time - time.time())

            if item is None:
                continue
            if item.prop == _prop:
                break

            processed_queue.put_nowait(item)
        else:
            item = None

        # To make sure that all received properties will be processed in the same order.
        with self.__queue_prop[tid].mutex:
            while self.__queue_prop[tid]._qsize() > 0:
                processed_queue.put(self.__queue_prop[tid]._get())

            while not processed_queue.empty():
                self.__queue_prop[tid]._put(processed_queue.get_nowait())

        return item

    def ip_send(self, pkt):
        pay = self.encode_i(SPINEL.PROP_STREAM_NET)

        pkt_len = len(pkt)
        pay += pack("<H", pkt_len)  # Start with length of IPv6 packet

        pkt_len += 2  # Increment to include length word
        pay += pkt  # Append packet after length

        self.transact(SPINEL.CMD_PROP_VALUE_SET, pay, SPINEL.HEADER_ASYNC)

    def chlist_send(self, pkt, chlist):
        pay = self.encode_i(chlist)

        pkt_len = len(pkt)
        pay += pack("<H", pkt_len)  # Start with length of chlist

        pkt_len += 2  # Increment to include length word
        pay += pkt  # Append packet after length

        self.transact(SPINEL.CMD_PROP_VALUE_SET, pay, SPINEL.HEADER_ASYNC)

    def cmd_reset(self):
        self.queue_wait_prepare(None, SPINEL.HEADER_ASYNC)
        self.transact(SPINEL.CMD_RESET)
        result = self.queue_wait_for_prop(SPINEL.PROP_LAST_STATUS,
                                          SPINEL.HEADER_ASYNC)
        return (result is not None and result.value == 114)

    def cmd_nverase(self):
        self.queue_wait_prepare(None, SPINEL.HEADER_ASYNC)
        self.transact(SPINEL.CMD_NVERASE)

    def cmd_send(self, command_id, payload=bytes(), tid=SPINEL.HEADER_DEFAULT):
        self.queue_wait_prepare(None, tid)
        self.transact(command_id, payload, tid)
        self.queue_wait_for_prop(None, tid)

    def prop_change_async(self,
                          cmd,
                          prop_id,
                          value,
                          py_format='B',
                          tid=SPINEL.HEADER_DEFAULT):
        pay = self.encode_i(prop_id)
        if py_format != None:
            pay += pack(py_format, value)
        self.transact(cmd, pay, tid)

    def prop_insert_async(self,
                          prop_id,
                          value,
                          py_format='B',
                          tid=SPINEL.HEADER_DEFAULT):
        self.prop_change_async(SPINEL.CMD_PROP_VALUE_INSERT, prop_id, value,
                               py_format, tid)

    def prop_remove_async(self,
                          prop_id,
                          value,
                          py_format='B',
                          tid=SPINEL.HEADER_DEFAULT):
        self.prop_change_async(SPINEL.CMD_PROP_VALUE_REMOVE, prop_id, value,
                               py_format, tid)

    def __prop_change_value(self,
                            cmd,
                            prop_id,
                            value,
                            py_format='B',
                            tid=SPINEL.HEADER_DEFAULT):
        """ Utility routine to change a property value over SPINEL. """
        self.queue_wait_prepare(prop_id, tid)

        pay = self.encode_i(prop_id)
        if py_format != None:
            pay += pack(py_format, value)
        self.transact(cmd, pay, tid)

        result = self.queue_wait_for_prop(prop_id, tid)

        if result:
            return result.value
        else:
            return None

    def prop_get_value(self, prop_id, tid=SPINEL.HEADER_DEFAULT):
        """ Blocking routine to get a property value over SPINEL. """
        if CONFIG.DEBUG_LOG_PROP:
            handler = SPINEL_PROP_DISPATCH[prop_id]
            prop_name = handler.__name__
            print("PROP_VALUE_GET [tid=%d]: %s" % (tid & 0xF, prop_name))
        return self.__prop_change_value(SPINEL.CMD_PROP_VALUE_GET, prop_id,
                                        None, None, tid)

    def prop_set_value(self,
                       prop_id,
                       value,
                       py_format='B',
                       tid=SPINEL.HEADER_DEFAULT):
        """ Blocking routine to set a property value over SPINEL. """
        if CONFIG.DEBUG_LOG_PROP:
            handler = SPINEL_PROP_DISPATCH[prop_id]
            prop_name = handler.__name__
            print("PROP_VALUE_SET [tid=%d]: %s" % (tid & 0xF, prop_name))
        return self.__prop_change_value(SPINEL.CMD_PROP_VALUE_SET, prop_id,
                                        value, py_format, tid)

    def prop_insert_value(self,
                          prop_id,
                          value,
                          py_format='B',
                          tid=SPINEL.HEADER_DEFAULT):
        """ Blocking routine to insert a property value over SPINEL. """
        if CONFIG.DEBUG_LOG_PROP:
            handler = SPINEL_PROP_DISPATCH[prop_id]
            prop_name = handler.__name__
            print("PROP_VALUE_INSERT [tid=%d]: %s" % (tid & 0xF, prop_name))
        return self.__prop_change_value(SPINEL.CMD_PROP_VALUE_INSERT, prop_id,
                                        value, py_format, tid)

    def prop_remove_value(self,
                          prop_id,
                          value,
                          py_format='B',
                          tid=SPINEL.HEADER_DEFAULT):
        """ Blocking routine to remove a property value over SPINEL. """
        if CONFIG.DEBUG_LOG_PROP:
            handler = SPINEL_PROP_DISPATCH[prop_id]
            prop_name = handler.__name__
            print("PROP_VALUE_REMOVE [tid=%d]: %s" % (tid & 0xF, prop_name))
        return self.__prop_change_value(SPINEL.CMD_PROP_VALUE_REMOVE, prop_id,
                                        value, py_format, tid)

    def get_ipaddrs(self, tid=SPINEL.HEADER_DEFAULT):
        """
        Return current list of ip addresses for the device.
        """
        value = self.prop_get_value(SPINEL.PROP_IPV6_ADDRESS_TABLE, tid)
        # TODO: clean up table parsing to be less hard-coded magic.
        if value is None:
            return None
        size = 0x1B
        addrs = [value[i:i + size] for i in range(0, len(value), size)]
        ipaddrs = []
        for addr in addrs:
            addr = addr[2:18]
            ipaddrs.append(ipaddress.IPv6Address(addr))
        return ipaddrs
