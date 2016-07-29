# local libs
import config
from base import Struct, StructError, UnpackError

# we don't need request message types here, or other bundles
MSG_TYPE_NULL = 0
MSG_TYPE_Error = 1
MSG_TYPE_EventData = 4
MSG_TYPE_SingleHostData = 6
MSG_TYPE_MultipleHostData = 7

class MessageBundle(Struct):

    __load_parsers__ = {
        'load_string': 'MSG_TYPE_',
        'load_type': 'vars',
    }

    _fields_ = [
        ('conn_id', 'uint32', 0),
        ('seq_num', 'uint32', 1),
    ]

    class MsgPeek(Struct):
        _fields_ = [('type', 'uint32', 0), ('length', 'uint32', 0)]

    __parsers__ = {}

    def __init__(self, *args, **kwargs):
        super(MessageBundle, self).__init__(*args, **kwargs)
        if args:
            #self.__unpack()
            self.__unpack(args[0])

    def __unpack(self,buf):
        self.messages = []
        unpack_data = self.data
        while len(unpack_data):
            try:
                peek = self.MsgPeek(unpack_data)
            except:
                break
            else:
                try:
                    parse_message = self.__parsers__[peek.type](unpack_data[8:peek.length+8])
                except (KeyError, UnpackError):
                    if len(unpack_data[8:peek.length+8]) == 0:
                        pass
                    else:
                        self.messages.append(unpack_data[8:peek.length+8])
                        unpack_data = unpack_data[peek.length+8:]
                else:
                    self.messages.append(parse_message)
                    unpack_data = unpack_data[peek.length+8:]
        
        self.data = self.messages

