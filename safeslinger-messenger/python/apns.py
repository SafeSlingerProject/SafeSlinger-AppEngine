# PyAPNs was developed by Simon Whitaker <simon@goosoftware.co.uk>
# Source available at https://github.com/simonwhitaker/PyAPNs
#
# PyAPNs is distributed under the terms of the MIT license.
#
# Copyright (c) 2011 Goo Software Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from binascii import a2b_hex, b2a_hex
from datetime import datetime
from socket import socket, timeout, AF_INET, SOCK_STREAM
from socket import error as socket_error
from struct import pack, unpack
import sys
import ssl
import select
import time
import collections, itertools
import logging
import threading
import StringIO

try:
    from ssl import wrap_socket, SSLError
except ImportError:
    from socket import ssl as wrap_socket, sslerror as SSLError

from _ssl import SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE

try:
    import json
except ImportError:
    import simplejson as json

_logger = logging.getLogger(__name__)

MAX_PAYLOAD_LENGTH = 256

NOTIFICATION_COMMAND = 0
ENHANCED_NOTIFICATION_COMMAND = 1

NOTIFICATION_FORMAT = (
     '!'   # network big-endian
     'B'   # command
     'H'   # token length
     '32s' # token
     'H'   # payload length
     '%ds' # payload
    )

ENHANCED_NOTIFICATION_FORMAT = (
     '!'   # network big-endian
     'B'   # command
     'I'   # identifier
     'I'   # expiry
     'H'   # token length
     '32s' # token
     'H'   # payload length
     '%ds' # payload
    )

ERROR_RESPONSE_FORMAT = (
     '!'   # network big-endian
     'B'   # command
     'B'   # status
     'I'   # identifier
    )

TOKEN_LENGTH = 32
ERROR_RESPONSE_LENGTH = 6
SENT_BUFFER_QTY = 100000
WAIT_WRITE_TIMEOUT_SEC = 10
WAIT_READ_TIMEOUT_SEC = 0.1

ER_STATUS = 'status'
ER_IDENTIFER = 'identifier'

class APNs(object):
    """
    A class representing an Apple Push Notification service connection
    """

    def __init__(self, use_sandbox=False, cert_file=None, key_file=None, enhanced=False):
        """
        Set use_sandbox to True to use the sandbox (test) APNs servers.
        Default is False.
        """
        super(APNs, self).__init__()
        self.use_sandbox = use_sandbox
        self.cert_file = cert_file
        self.key_file = key_file
        self._feedback_connection = None
        self._gateway_connection = None
        self.enhanced = enhanced

    @staticmethod
    def packed_uchar(num):
        """
        Returns an unsigned char in packed form
        """
        return pack('>B', num)

    @staticmethod
    def packed_ushort_big_endian(num):
        """
        Returns an unsigned short in packed big-endian (network) form
        """
        return pack('>H', num)

    @staticmethod
    def unpacked_ushort_big_endian(bytes):
        """
        Returns an unsigned short from a packed big-endian (network) byte
        array
        """
        return unpack('>H', bytes)[0]

    @staticmethod
    def packed_uint_big_endian(num):
        """
        Returns an unsigned int in packed big-endian (network) form
        """
        return pack('>I', num)

    @staticmethod
    def unpacked_uint_big_endian(bytes):
        """
        Returns an unsigned int from a packed big-endian (network) byte array
        """
        return unpack('>I', bytes)[0]
    
    @staticmethod
    def unpacked_char_big_endian(bytes):
        """
        Returns an unsigned char from a packed big-endian (network) byte array
        """
        return unpack('c', bytes)[0]

    @property
    def feedback_server(self):
        if not self._feedback_connection:
            self._feedback_connection = FeedbackConnection(
                use_sandbox = self.use_sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._feedback_connection

    @property
    def gateway_server(self):
        if not self._gateway_connection:
            self._gateway_connection = GatewayConnection(
                use_sandbox = self.use_sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file,
                enhanced = self.enhanced
            )
        return self._gateway_connection


class APNsConnection(object):
    """
    A generic connection class for communicating with the APNs
    """
    def __init__(self, cert_file=None, key_file=None, timeout=None, enhanced=False):
        super(APNsConnection, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.timeout = timeout
        self._socket = None
        self._ssl = None
        self.enhanced = enhanced
        self.connection_alive = False

    def __del__(self):
        self._disconnect();

    def _connect(self):
        # Establish an SSL connection
        _logger.debug("%s APNS connection establishing..." % self.__class__.__name__)

        # Fallback for socket timeout.
        for i in xrange(3):
            try:
                self._socket = socket(AF_INET, SOCK_STREAM)
                self._socket.settimeout(self.timeout)
                self._socket.connect((self.server, self.port))
                break
            except timeout:
                pass
            except:
                raise

        if self.enhanced:
            self._last_activity_time = time.time()
            self._socket.setblocking(False)
            self._ssl = wrap_socket(self._socket, server_side=False, keyfile=StringIO.StringIO(self.key_file), certfile=StringIO.StringIO(self.cert_file), do_handshake_on_connect=False)
            
            while True:
                try:
                    self._ssl.do_handshake()
                    break
                except ssl.SSLError, err:
                    if ssl.SSL_ERROR_WANT_READ == err.args[0]:
                        select.select([self._ssl], [], [])
                    elif ssl.SSL_ERROR_WANT_WRITE == err.args[0]:
                        select.select([], [self._ssl], [])
                    else:
                        raise

        else:
            # Fallback for 'SSLError: _ssl.c:489: The handshake operation timed out'
            for i in xrange(3):
                try:
                    self._ssl = wrap_socket(self._socket, server_side=False, keyfile=StringIO.StringIO(self.key_file), certfile=StringIO.StringIO(self.cert_file), do_handshake_on_connect=False)
                    break
                except SSLError, ex:
                    if ex.args[0] == SSL_ERROR_WANT_READ:
                        sys.exc_clear()
                    elif ex.args[0] == SSL_ERROR_WANT_WRITE:
                        sys.exc_clear()
                    else:
                        raise
        
        self.connection_alive = True
        _logger.debug("%s APNS connection established" % self.__class__.__name__)

    def _disconnect(self):
        if self.connection_alive:
            if self._socket:
                self._socket.close()
            if self._ssl:
                self._ssl.close()
            self.connection_alive = False
            _logger.info(" %s APNS connection closed" % self.__class__.__name__)

    def _connection(self):
        if not self._ssl or not self.connection_alive:
            self._connect()
        return self._ssl

    def read(self, n=None):
        return self._connection().read(n)

    def write(self, string):
        if self.enhanced: # nonblocking socket
            self._last_activity_time = time.time()
            _, wlist, _ = select.select([], [self._connection()], [], WAIT_WRITE_TIMEOUT_SEC)
            
            if len(wlist) > 0:
                length = self._connection().sendall(string)
                if length == 0:
                    _logger.debug("sent length: %d" % length) #DEBUG
            else:
                _logger.warning("write socket descriptor is not ready after " + str(WAIT_WRITE_TIMEOUT_SEC))
            
        else: # blocking socket
            return self._connection().write(string)


class PayloadAlert(object):
    def __init__(self, body, action_loc_key=None, loc_key=None,
                 loc_args=None, launch_image=None):
        super(PayloadAlert, self).__init__()
        self.body = body
        self.action_loc_key = action_loc_key
        self.loc_key = loc_key
        self.loc_args = loc_args
        self.launch_image = launch_image
    
    def dict(self):
        d = { 'body': self.body }
        if self.action_loc_key:
            d['action-loc-key'] = self.action_loc_key
        if self.loc_key:
            d['loc-key'] = self.loc_key
        if self.loc_args:
            d['loc-args'] = self.loc_args
        if self.launch_image:
            d['launch-image'] = self.launch_image
        return d

class PayloadTooLargeError(Exception):
    def __init__(self):
        super(PayloadTooLargeError, self).__init__()

class Payload(object):
    """
    A class representing an APNs message payload
    """
    def __init__(self, alert=None, badge=None, sound=None, custom={}):
        super(Payload, self).__init__()
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.custom = custom
        self._check_size()
    
    def dict(self):
        """
        Returns the payload as a regular Python dictionary
        """
        d = {}
        if self.alert:
            # Alert can be either a string or a PayloadAlert
            # object
            if isinstance(self.alert, PayloadAlert):
                d['alert'] = self.alert.dict()
            else:
                d['alert'] = self.alert
        if self.sound:
            d['sound'] = self.sound
        if self.badge is not None:
            d['badge'] = int(self.badge)
        
        d.update(self.custom)
        d = { 'aps': d }
        return d
    
    def json(self):
        return json.dumps(self.dict(), separators=(',',':'), ensure_ascii=False).encode('utf-8')
    
    def _check_size(self):
        if len(self.json()) > MAX_PAYLOAD_LENGTH:
            raise PayloadTooLargeError()
    
    def __repr__(self):
        attrs = ("alert", "badge", "sound", "custom")
        args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s)" % (self.__class__.__name__, args)

class Frame(object):
    """A class representing an APNs message frame for multiple sending"""
    def __init__(self):
        self.frame_data = bytearray()
        self.notification_data = list()

    def get_frame(self):
        return self.frame_data

    def add_item(self, token_hex, payload, identifier, expiry, priority):
        """Add a notification message to the frame"""
        item_len = 0
        self.frame_data.extend('\2' + APNs.packed_uint_big_endian(item_len))

        token_bin = a2b_hex(token_hex)
        token_length_bin = APNs.packed_ushort_big_endian(len(token_bin))
        token_item = '\1' + token_length_bin + token_bin
        self.frame_data.extend(token_item)
        item_len += len(token_item)

        payload_json = payload.json()
        payload_length_bin = APNs.packed_ushort_big_endian(len(payload_json))
        payload_item = '\2' + payload_length_bin + payload_json
        self.frame_data.extend(payload_item)
        item_len += len(payload_item)

        identifier_bin = APNs.packed_uint_big_endian(identifier)
        identifier_length_bin = \
                APNs.packed_ushort_big_endian(len(identifier_bin))
        identifier_item = '\3' + identifier_length_bin + identifier_bin
        self.frame_data.extend(identifier_item)
        item_len += len(identifier_item)

        expiry_bin = APNs.packed_uint_big_endian(expiry)
        expiry_length_bin = APNs.packed_ushort_big_endian(len(expiry_bin))
        expiry_item = '\4' + expiry_length_bin + expiry_bin
        self.frame_data.extend(expiry_item)
        item_len += len(expiry_item)

        priority_bin = APNs.packed_uchar(priority)
        priority_length_bin = APNs.packed_ushort_big_endian(len(priority_bin))
        priority_item = '\5' + priority_length_bin + priority_bin
        self.frame_data.extend(priority_item)
        item_len += len(priority_item)

        self.frame_data[-item_len-4:-item_len] = APNs.packed_uint_big_endian(item_len)

        self.notification_data.append({'token':token_hex, 'payload':payload, 'identifier':identifier, 'expiry':expiry, "priority":priority})

    def get_notifications(self, gateway_connection):
        notifications = list({'id': x['identifier'], 'message':gateway_connection._get_enhanced_notification(x['token'], x['payload'],x['identifier'], x['expiry'])} for x in self.notification_data)
        return notifications

    def __str__(self):
        """Get the frame buffer"""
        return str(self.frame_data)

class FeedbackConnection(APNsConnection):
    """
    A class representing a connection to the APNs Feedback server
    """
    def __init__(self, use_sandbox=False, **kwargs):
        super(FeedbackConnection, self).__init__(**kwargs)
        self.server = (
            'feedback.push.apple.com',
            'feedback.sandbox.push.apple.com')[use_sandbox]
        self.port = 2196

    def _chunks(self):
        BUF_SIZE = 4096
        while 1:
            data = self.read(BUF_SIZE)
            yield data
            if not data:
                break

    def items(self):
        """
        A generator that yields (token_hex, fail_time) pairs retrieved from
        the APNs feedback server
        """
        buff = ''
        for chunk in self._chunks():
            buff += chunk

            # Quit if there's no more data to read
            if not buff:
                break

            # Sanity check: after a socket read we should always have at least
            # 6 bytes in the buffer
            if len(buff) < 6:
                break

            while len(buff) > 6:
                token_length = APNs.unpacked_ushort_big_endian(buff[4:6])
                bytes_to_read = 6 + token_length
                if len(buff) >= bytes_to_read:
                    fail_time_unix = APNs.unpacked_uint_big_endian(buff[0:4])
                    fail_time = datetime.utcfromtimestamp(fail_time_unix)
                    token = b2a_hex(buff[6:bytes_to_read])

                    yield (token, fail_time)

                    # Remove data for current token from buffer
                    buff = buff[bytes_to_read:]
                else:
                    # break out of inner while loop - i.e. go and fetch
                    # some more data and append to buffer
                    break

class GatewayConnection(APNsConnection):
    """
    A class that represents a connection to the APNs gateway server
    """
    
    def __init__(self, use_sandbox=False, **kwargs):
        super(GatewayConnection, self).__init__(**kwargs)
        self.server = (
            'gateway.push.apple.com',
            'gateway.sandbox.push.apple.com')[use_sandbox]
        self.port = 2195
        if self.enhanced == True: #start error-response monitoring thread       
            self._last_activity_time = time.time()
            self._send_lock = threading.RLock()
            self._sent_notifications = collections.deque(maxlen=SENT_BUFFER_QTY)

    def _get_notification(self, token_hex, payload):
        """
        Takes a token as a hex string and a payload as a Python dict and sends
        the notification
        """
        token_bin = a2b_hex(token_hex)
        token_length_bin = APNs.packed_ushort_big_endian(len(token_bin))
        payload_json = payload.json()
        payload_length_bin = APNs.packed_ushort_big_endian(len(payload_json))
        
        notification = ('\0' + token_length_bin + token_bin
            + payload_length_bin + payload_json)

        return notification

    def _get_enhanced_notification(self, token_hex, payload, identifier, expiry):
        """
        form notification data in an enhanced format
        """
        token_bin = a2b_hex(token_hex)
        token_length_bin = APNs.packed_ushort_big_endian(len(token_bin))
        payload_json = payload.json()
        payload_length_bin = APNs.packed_ushort_big_endian(len(payload_json))
        _identifier = APNs.packed_uint_big_endian(identifier)
        _expiry = APNs.packed_uint_big_endian(expiry)
        
        notification = ('\1' + _identifier + _expiry + token_length_bin + token_bin
            + payload_length_bin + payload_json)
        return notification
         
    def send_notification(self, token_hex, payload, identifier=0, expiry=0):
        """
        in enhanced mode, send_notification may return error response from APNs if any
        """
        if self.enhanced:
            self._last_activity_time = time.time()
            message = self._get_enhanced_notification(token_hex, payload,
                                                           identifier, expiry)
            timeout_sec = 2
            timeout_tot = 0
            i = 0
            _error = 0 # no errors
            while timeout_tot < 30:
                try:
                    with self._send_lock:
                        timeout_tot += timeout_sec
                        i += 1
                        self.write(message)
                        self._sent_notifications.append(dict({'id': identifier, 'message': message}))
                        rlist, _, _ = select.select([self._connection()], [], [], WAIT_READ_TIMEOUT_SEC)
                        if len(rlist) > 0: # there's some data from APNs
                            self._socket.settimeout(0.1)
                            buff = self.read(ERROR_RESPONSE_LENGTH)
                            if len(buff) == ERROR_RESPONSE_LENGTH:
                                command, status, identifier = unpack(ERROR_RESPONSE_FORMAT, buff)
                                if 8 == command: # there is error response from APNS
                                    _logger.info("got error-response from APNS: %d" % status)
                                _error = status
                        else:
                            _logger.info("Successfully Sent Notification to APNS.") #DEBUG
                        self._disconnect()
                    break
                except socket_error as e:
                    _error = 10
                    timeout_sec *= 2
                    _logger.exception("sending notification with id:" + str(identifier) + 
                                      " to APNS failed: " + str(type(e)) + ": " + str(e) + 
                                      " in " + str(i+1) + "th attempt, will wait " + str(timeout_sec) + 
                                      " secs for next action")
                    time.sleep(timeout_sec) # wait potential error-response to be read
            return _error
        else:
            self.write(self._get_notification(token_hex, payload))
            return True

    def send_notification_multiple(self, frame):
        self._sent_notifications += frame.get_notifications(self)
        return self.write(frame.get_frame())
    
    def _is_idle_timeout(self):
        TIMEOUT_IDLE = 30
        return (time.time() - self._last_activity_time) >= TIMEOUT_IDLE
