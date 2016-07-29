from base import Struct

class Error(Struct):
    _fields_ = [
        ('code', 'int32', 0),
        ('length', 'uint16', 0),
        ('error_msg', 'variable', 0),
    ]
