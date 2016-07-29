# local libs
import config
from base import Struct, UnpackError

# std libs
import struct

''' default header version we support '''
HEADER_VERSION = 1

'''
These are the message types supported
We can point to a local class or to a module
see the __load_parsers__ dict and the __new__
definition in the metaclass in base.py
'''
MSG_TYPE_NULL = 0
MSG_TYPE_Error = 1
MSG_TYPE_EventRequest = 2
MSG_TYPE_EventData = 4
MSG_TYPE_HostDataRequest = 5
MSG_TYPE_SingleHostData = 6
MSG_TYPE_MultipleHostData = 7
MSG_TYPE_StreamingRequest = 2049
MSG_TYPE_StreamingInfo = 2051
MSG_TYPE_MessageBundle = 4002

class MessageHeaderError(): pass

'''
ver - header version (always 1)
type - message type sent
length - message length excluding header (ver and type)
'''
class MessageHeader(Struct):


    __load_parsers__ = {
        'load_string': 'MSG_TYPE_',
        'load_type': 'vars',
    }
    _fields_ = [
        ('ver', 'uint16', HEADER_VERSION),
        ('type', 'uint16', 0),
        ('length', 'uint32', 0),
    ]
    # track  loaded parsers
    __parsers__ = {}

    def __init__(self, *args, **kwargs):
        super(MessageHeader, self).__init__(*args, **kwargs)
        if args:
            if self.type != MSG_TYPE_NULL and self.type != MSG_TYPE_StreamingInfo:
                self.__unpack(self.data)
        if not args and 'length' not in kwargs:
            self.length = len(self.data) if hasattr(self, 'data') else 0

    def __unpack(self, buf):
        try:
            self.data = self.__parsers__[self.type](buf)
        except (KeyError, UnpackError):
            self.data = buf
