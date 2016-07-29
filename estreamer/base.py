from __future__ import unicode_literals

#local
import config
import inspect

#standard
from future.utils import raise_from
from six import with_metaclass, iteritems
import struct
import re


class Error(Exception): pass
class ArrayError(Error): pass
class StructError(Error): pass
class PackError(Error): pass
class UnpackError(Error): pass

class ArrayDesc(object):

    def __init__(self, name, obj):
        self.name = '__' + name
        self.obj = obj

    def __get__(self, instance, cls):
        return getattr(instance, self.name, None)
        
    def __set__(self, instance, value):
        loaded = self.obj.load_list(value)
        setattr(instance, self.name, loaded)
       

class StructArray(object):
    def __init__(self, *args):
        if args:
           if isinstance(args[0], type) and issubclass(args[0], Struct):
               self.structure_list = []
               self.structure_class = args[0]
           else:
               raise_from(ArrayError("Unsupported type"), type(args[0])) 
        else:
            raise_from(ArrayError("Array Error"), 'empty array')

    def load_subs(self, subs):
        self.structure_list = subs
        return self.structure_list

    def load_list(self, arr_list):
        self.structure_list = [self.structure_class(**init_args) for init_args in arr_list]
        return self.structure_list

    def get_struct(self):
        return ''.join([v for arr_struct in self.structure_list for k, v in iteritems(arr_struct._field_format_)])


class MetaStruct(type):

    endian_map = {'be': '>', 'le': '<', 'no': '>'}

    @classmethod
    def type_map(mcl, map):
        '''
        Table 1-2 lists the type conventions we map to 
        for the most part and handle others as we can.
        Source: 5.4 eStreamer integration guide
        '''
        _type_map = {
            'uint8': 'B', 'uint16': 'H', 'uint32': 'I',
            'int32': 'i', 'uint64': 'Q', 'variable': 'variable',
        }
        
        mapped = _type_map.get(map, None)
        # handle the other type convention cases
        if mapped is None:
            # allow a structure to be another structure (check if it's inherited)
            # or an array of structures
            if isinstance(map, StructArray) or (isinstance(map, type) and issubclass(map, Struct)):
                mapped = map
            else:
                ''' the array values always use unsigned '''
                match_obj = re.match(r'(uint\d+)\[(\d+)\]', map)
                if match_obj:
                    try:
                        tm = _type_map[match_obj.group(1)]
                    except KeyError:
                        raise StructError("invalid type mapping: {}".format(match_obj.group(1)))
                    else:
                        mapped = tm * int(match_obj.group(2))
                else:
                    raise StructError("invalid type mapping: {}".format(map))
        return mapped

    '''
    auto-create class variables before creating the object using
    the python 'ctypes'-like meta (even with the same _fields_ name..))
    setup extended fields when requesting 'timestamp' records
    auto-import parser modules/classes
    '''
    def __new__(mcl, name, bases, nmspc):
        ''' handle parser loading for modules and local classes via LoadParsers class '''
        lp_dict = nmspc.get('__load_parsers__', False)
        if lp_dict and not nmspc.get('__parsers__', None):
            # send the module name over, so we can get the class members
            lp = config.LoadParsers(inspect.getmodule(inspect.stack()[1][0]))
            lp.load_from(lp_dict['load_type'], lp_dict['load_string'])
            nmspc['__parsers__'] = lp.instance_dict

        # make sure that field structure is defined
        if nmspc.get('_fields_', None) is not None:
            fields = nmspc['_fields_']
          
            '''
            try to save some overhead by using __slots__ since we'll use the same structures over and over
            we can only define __slots__ at  __new__
            '''
            nmspc['__slots__'] = ['__parsers__', 'endian', '_field_names_', '_field_format_', 'data'] + [field[0] for field in fields]
            # default to big endian / network byte order
            nmspc['endian'] = MetaStruct.endian_map.get(nmspc.get('_endian_', 'be'), '>')
            # put the names of all the fields in one attribute for easier access later
            nmspc['_field_names_'] = [field[0] for field in fields]
            # create a dict for each fields' and/or attributes' parsing format
            nmspc['_field_format_'] = dict(zip(nmspc['_field_names_'], [MetaStruct.type_map(field[1]) for field in fields]))
            # set the default values
            for field in fields:
                if isinstance(nmspc['_field_format_'][field[0]], StructArray):
                    nmspc[field[0]] = ArrayDesc(field[0], nmspc['_field_format_'][field[0]])
                else:
                    nmspc[field[0]] = field[2]
        return type.__new__(mcl, name, bases, nmspc)

class Struct(with_metaclass(MetaStruct, object)):
   # __metaclass__ = MetaStruct

    _struct_flags = 0
    _struct_timestamp = 0

    @classmethod
    def set_flags(self, flags):
        self._struct_flags = flags

    @classmethod
    def get_flags(self):
        return self._struct_flags

    @classmethod
    def set_ts(self, ts):
        self._struct_timestamp = ts

    @classmethod
    def get_ts(self):
        return self._struct_timestamp

    def unpack(self, buf):
        self.data = ''
        for field in self._field_names_:
            fmt = self._field_format_[field]
            if isinstance(fmt, StructArray): # TODO: better way to handle the pack/unpack for this
                sc_list = []
                for struct_item in range(len(buf) / len(fmt.structure_class())):
                    cls_sarr = fmt.structure_class(buf[:len(fmt.structure_class())])
                    cls_sarr_cp = deepcopy(cls_sarr)
                    sc_list.append(cls_sarr_cp)
                    buf = buf[len(fmt.structure_class()):]
                setattr(self, field, fmt.load_subs(sc_list))
                self._field_format_[field] = fmt.get_struct()
            # check if it's a class of Struct
            elif isinstance(fmt, type) and issubclass(fmt, Struct):
                setattr(self, field, fmt(buf))
                if hasattr(getattr(self, field), 'data'):
                    buf = getattr(getattr(self, field), 'data')
            elif fmt.startswith('BBB') or fmt.startswith('bbb'):
                val, buf = self.__unpack__(fmt, buf)
                setattr(self, field, sum([byte_ << (offset * 8) for offset, byte_ in enumerate(val)]))
            elif (fmt == "variable" or fmt[-1] == 's') and 'val_or_length' in locals():
                val_len = (val_or_length[0] - self.__sub_length__) if hasattr(self, '__sub_length__') else val_or_length[0]
                fmt = str(val_len) + 's'
                self._field_format_[field] = fmt
                val, buf = self.__unpack__(fmt, buf, val_len)
                setattr(self, field, val[0])
            else:
              val_or_length, buf = self.__unpack__(fmt, buf)
              setattr(self, field, val_or_length[0])
        if buf:
            self.data = buf

    def __unpack__(self, type_, buf, _size=None):
        fmt = self.endian + type_
        size = struct.calcsize(fmt) if _size is None else _size
        try:
            unpacked = struct.unpack(fmt, buf[:size]), buf[size:]
        except struct.error as exc:
            raise_from(UnpackError("Unable to unpack structure"), exc)
        else:
            return unpacked

    def __init__(self, *args, **kwargs):
            
        if args:
            self.unpack(args[0])
        ''' build the struct from kwargs and set the pack format for variable fields '''
        if kwargs:
            for k, v in iteritems(kwargs):
                fmt = self._field_format_.get(k, '')
                if fmt == 'variable':
                    self._field_format_[k] = len(v) + 's'
                setattr(self, k, v)

    def __pack__(self):
        fmt = self.endian
        value_list = []
        for field in self._field_names_:
            fmt_ = self._field_format_[field]
            val = getattr(self, field)
            if isinstance(fmt_, StructArray):
                value_list.extend([
                    getattr(struct_, field)
                    for struct_ in fmt_.structure_list
                    for field in struct_._field_names_
                ])
            elif isinstance(fmt_, basestring) and (fmt_.startswith('BBB') or fmt_.startswith('bbb')):
                value_list.extend([(val >> i & 0xFF) for i in [x for x in range(0, len(fmt_) * 8, 8)]])
            else:    
                try:
                    value_list.append(val.encode('ascii', 'ignore'))
                except AttributeError:
                    value_list.append(val)
            fmt += str(len(val)) + 's' if fmt_ == 'variable' else fmt_.get_struct() if isinstance(fmt_, StructArray) else fmt_
        try:
            return struct.pack(fmt, *value_list)
        except struct.error as exc:
            raise_from(PackError("Unable to pack structure"), exc)

    def pack(self):
        return str(self)

    ''' pack fields + data, if data exists, otherwise, just pack the fields '''
    def __str__(self):
        return str(self.__pack__()) + str(self.data) if hasattr(self, 'data') and len(self.data) else str(self.__pack__())

    def __repr__(self):
        repr_list = []
        for field in self._field_names_:
            # handle dynamic structs (e.g., archival stamp); just ignore fields that don't exist
            try:
                field_val = getattr(self, field)
            except AttributeError as exc:
                pass
            else:
                if hasattr(field_val, '__sub_length__'):
                    repr_list.append('{}={}'.format(field, repr(field_val)))
                try:
                    repr_list.append('{}={}'.format(field, field_val))
                except UnicodeDecodeError:
                    pass
        if hasattr(self, 'data') and not getattr(self, '__hide_data__', None) and len(self.data):
            repr_list.append('data={}'.format(repr(self.data)))
        return '<{}({})>'.format(self.__class__.__name__, ', '.join(repr_list))

    ''' 
    we will use the struct calcsize to determine the 'length' of each layer (+ the length of data)
    '''
    def __len__(self):
        fmt = ''
        more_len = 0
        for field in self._field_names_:
            fmt_ = self._field_format_[field]
            if isinstance(fmt_, StructArray):
                fmt += fmt_.get_struct()
            elif isinstance(fmt_, type) and issubclass(fmt_, Struct):
                more_len = len(fmt)
            elif fmt_ != 'variable':
                fmt += fmt_
        hdr_len = struct.calcsize(fmt) + more_len
        if hasattr(self, 'data'):
            hdr_len += len(self.data)
        return hdr_len
