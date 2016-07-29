#local
from message import MessageHeader
from base import Struct, StructArray

#standard
from datetime import datetime
from ctypes import LittleEndianStructure, Union, c_uint32
from six import iteritems, raise_from
import inspect
import config
import sys

class Error(Exception): pass
class InvalidTimestampError(Error): pass
class InvalidFlagError(Error): pass

class INTRUSION_EVENTS(object):
    version = 8 # 5.4+
    code = 12
class METADATA(object):
    version = 4 #4.7+
    code = 21
class CORRELATION(object):
    version = 9 #5.4+
    code = 31
class DISCOVERY(object):
    version = 11 #5.3.1+
    code = 61
class CONNECTION(object):
    version = 12 #5.4+
    code = 71
class USER(object):
    version = 4 #5.2+
    code = 91
class MALWARE(object):
    version = 6 #5.4+
    code = 101
class FILE(object):
    version = 5 #5.4+
    code = 111
class IMPACT(object):
    version = 2 #5.3+
    code = 131
class TERMINATE(object):
    version = 0
    code = 0

class StreamingEventType(Struct):
    _fields_ = [
        ('version', 'uint16', 0),
        ('code', 'uint16', 0),
    ]

class StreamingEventRequest(Struct):
    _fields_ = [
        ('type', 'uint32', 6667),
        ('length', 'uint32', 0),
        ('flags', 'uint32', 0),
        ('timestamp', 'uint32', 0),
        ('service_array', StructArray(StreamingEventType), None)
    ]
    def __init__(self, *args, **kwargs):
        super(StreamingEventRequest, self).__init__(*args, **kwargs)
        if 'length' not in kwargs:
            self.length = sum([len(i) for i in self.service_array] + [16])

class FlagBits(LittleEndianStructure):
    _fields_ = [
        ('packets', c_uint32, 1),
        ('metadata', c_uint32, 1),
        ('ids', c_uint32, 1),
        ('discovery', c_uint32, 1),
        ('correlation', c_uint32, 1),
        ('impact', c_uint32, 1),
        ('ids_1', c_uint32, 1),
        ('discovery_v2', c_uint32, 1),
        ('connection', c_uint32, 1),
        ('correlation_v2', c_uint32, 1),
        ('discovery_v3', c_uint32, 1),
        ('disable_events', c_uint32, 1),
        ('connection_v3', c_uint32, 1),
        ('correlation_v3', c_uint32, 1),
        ('metadata_v2', c_uint32, 1),
        ('metadata_v3', c_uint32, 1),
        ('reserved', c_uint32, 1),
        ('discovery_v4', c_uint32, 1),
        ('connection_v4', c_uint32, 1),
        ('correlation_v4', c_uint32, 1),
        ('metadata_v4', c_uint32, 1),
        ('user', c_uint32, 1),
        ('correlation_v5', c_uint32, 1),
        ('timestamp', c_uint32, 1),
        ('discovery_v5', c_uint32, 1),
        ('discovery_v6', c_uint32, 1),
        ('connection_v5', c_uint32, 1),
        ('extra_data', c_uint32, 1),
        ('discovery_v7', c_uint32, 1),
        ('correlation_v6', c_uint32, 1),
        ('extended_request', c_uint32, 1),
    ]

class Flags(Union):
    _fields_ = [
        ('flag', FlagBits),
        ('from_bytes', c_uint32)
    ]

class EventRequest(Struct):
    _fields_ = [
        ('timestamp', 'uint32', 0xFFFFFFFF),
        ('flags', 'uint32', 0x40800001)
    ]

'''
 Extended Request Event code and versioning
'''
class RequestEvent(object):
  

    def __init__(self, start_from, **kwargs):
        self.flags = Flags()
        if start_from == 0 or start_from == 0xFFFFFFFF:
            self.timestamp = start_from
        else:
            try:
                datetime.fromtimestamp(start_from)
            except TypeError as exc:
                raise_from(InvalidTimestampError('Timestamp invalid (0, 0xFFFFFFFF, or Unix Timestamp'), exc)
            else:
                self.timestamp = start_from
        for k,v in iteritems(kwargs):
            try:
              getattr(self.flags.flag, k)
              setattr(self.flags.flag, k, int(v))
            except AttributeError as exc:
                raise_from(InvalidFlagError('Invalid flag: {}'.format(k)), exc)

        # save the timestamp and flags for reuse (if needed)
        Struct.set_ts(self.timestamp)
        Struct.set_flags(self.flags.from_bytes)
        # build the request
        self.event_request = EventRequest(timestamp=self.timestamp,flags=self.flags.from_bytes)
        self.message_header =  MessageHeader(type=2, data=self.event_request.pack())
        self.record = self.message_header.pack()
        

class StreamEventRequest(object):
    def __init__(self, type_list):
        mod_name = sys.modules[__name__]
        cls_list = [
            cls[0]
            for cls in inspect.getmembers(mod_name)
            if cls[0].isupper() and inspect.isclass(cls[1]) and cls[1].__module__ == __name__
        ]
        try:
            type_list.remove('TERMINATE') # can't hold order, so remove it and add it back when done
        except ValueError as exc:
            pass
        type_list = list(set(type_list).intersection(set(cls_list))) # remove bad and duplicate values
        array_args = [
            {'version': getattr(getattr(mod_name, rtype), 'version'), 
            'code': getattr(getattr(mod_name, rtype), 'code')}
            for rtype in type_list
        ]
        array_args.append({'code': 0, 'version': 0}) # add TERMINATE as last req
        self.streaming_event_request = StreamingEventRequest(service_array=array_args, timestamp=Struct.get_ts(), flags=Struct.get_flags())
        self.message_header = MessageHeader(type=2049, data=self.streaming_event_request)
	self.record = self.message_header.pack() 
