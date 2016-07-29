
# standard libs
import socket
import struct
import inspect
import os
import imp
import sys

PRIORITY_NAME = {
    1: 'High',
    2: 'Medium',
    4: 'Low',
}

EXTRA_DATA_TYPE = {
    1: 'XFF client (IPv4)',
    2: 'XFF client (IPv6)',
    3: 'HTTP URI',
}

FILE_DISPOSITION = {
    1: 'CLEAN',
    2: 'UNKNOWN',
    3: 'MALWARE',
    4: 'UNAVAILABLE',
    5: 'CUSTOM SIGNATURE',
}
FILE_STORAGE = {
    1: 'File Stored',
    2: 'File Stored',
    3: 'Unable to Store File',
    4: 'Unable to Store File',
    5: 'Unable to Store File',
    6: 'Unable to Store File',
    7: 'Unable to Store File',
    8: 'File Size is Too Large',
    9: 'File Size is Too Small',
    10: 'Unable to Store File',
    11: 'File Not Stored, Disposition Unavailable'
}
FILE_ANALYSIS_STATUS = {
    0: 'File Not Sent for Analysis',
    1: 'Sent for Analysis',
    2: 'Sent for Analysis',
    4: 'Sent for Analysis',
    5: 'Failed to Send',
    6: 'Failed to Send',
    7: 'Failed to Send',
    8: 'Failed to Send',
    9: 'File Size is Too Small',
    10: 'File Size is Too Large',
    11: 'Sent for Analysis',
    12: 'Analysis Complete',
    13: 'Failure (Network Issue)',
    14: 'Failure (Rate Limit)',
    15: 'Failure (File Too Large)',
    16: 'Failure (File Read Error)',
    17: 'Failure (Internal Library Error)',
    19: 'File Not Sent, Disposition Unavailable',
    20: 'Failure (Cannot Run File)',
    21: 'Failure (Analysis Timeout)',
    22: 'Sent for Analysis',
    23: 'File Not Supported',
}
FILE_ACTION = {
    1: 'Detect',
    2: 'Block',
    3: 'Malware Cloud Lookup',
    4: 'Malware Block',
    5: 'Malware Whitelist',
    6: 'Cloud Lookup Timeout',
    7: 'Custom Detection',
    8: 'Custom Detection Block,',
    9: 'Archive Block (Depth Exceeded)',
    10: 'Archive Block (Encrypted)',
    11: 'Archive Block (Failed to Inspect)',
}
FILE_DIRECTION = {
    1: 'Download',
    2: 'Upload',
}

SSL_ACTION = {
    0: 'Unknown',
    1: 'Do Not Decrypt',
    2: 'Block',
    3: 'Block With Reset',
    4: 'Decrypt (Known Key)',
    5: 'Decrypt (Replace Key)',
    6: 'Decrypt (Resign)',
}

SSL_FLOW_STATUS = {
    0: 'Unknown',
    1: 'No Match',
    2: 'Success',
    3: 'Uncached Session',
    4: 'Unknown Cipher Suite',
    5: 'Unsupported Cipher Suite',
    6: 'Unsupported SSL Version',
    7: 'SSL Compression Used',
    8: 'Session Undecryptable in Passive Mode',
    9: 'Handshake Error',
    10: 'Decryption Error',
    11: 'Pending Server Name Category Lookup',
    12: 'Pending Common Name Category Lookup',
    13: 'Internal Error',
    14: 'Network Parameters Unavailable',
    15: 'Invalid Server Certificate Handle',
    16: 'Server Certificate Fingerprint Unavailable',
    17: 'Cannot Cache Subject DN',
    18: 'Cannot Cache Issuer DN',
    19: 'Unknown SSL Version',
    20: 'External Certificate List Unavailable',
    21: 'External Certificate Fingerprint Unavailable',
    22: 'Internal Certificate List Invalid',
    23: 'Internal Certificate List Unavailable',
    24: 'Internal Certificate Unavailable',
    25: 'Internal Certificate Fingerprint Unavailable',
    26: 'Server Certificate Validation Unavailable',
    27: 'Server Certificate Validation Failure',
    28: 'Invalid Action',
}

USER_DEFINED = {
    0: 'Defined by AMP',
    1: 'User Defined',
}


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

ARCHIVAL_RCD_TYPES = [2, 400, 9, 110, 111, 112, 125, 207, 208]

RCD_TYPE_Packet = 2
RCD_TYPE_Priority = 4
RCD_TYPE_Impact = 9
RCD_TYPE_User = 62
RCD_TYPE_RuleMeta = 66
RCD_TYPE_Classification = 67
RCD_TYPE_CorrelationPolicy = 69
RCD_TYPE_CorrelationRule = 70
RCD_TYPE_ExtraData = 110
RCD_TYPE_ExtraMeta = 111
RCD_TYPE_CorrelationEvent = 112
RCD_TYPE_SecurityZone = 115
RCD_TYPE_InterfaceName = 116
RCD_TYPE_AccessControlPolicy = 117
RCD_TYPE_IntrusionPolicy = 118
RCD_TYPE_AccessControlRuleID = 119
RCD_TYPE_AccessControlRuleAction = 120
RCD_TYPE_URLCategory = 121
RCD_TYPE_URLReputation = 122
RCD_TYPE_ManagedDevice = 123
RCD_TYPE_MalwareEvent = 125
RCD_TYPE_SecurityIntel = 127
RCD_TYPE_MalwareEventTypeMeta = 128
RCD_TYPE_MalwareEventSubtypeMeta = 129
RCD_TYPE_FireAMPDetector = 130
RCD_TYPE_FireAMPFile = 131
RCD_TYPE_SecurityContext = 132
RCD_TYPE_ICMPType = 260
RCD_TYPE_ICMPCode = 270
RCD_TYPE_IntrusionEvent = 400
RCD_TYPE_FileEvent = 500
RCD_TYPE_FileEvent2 = 502
RCD_TYPE_RuleDocumentation = 510
RCD_TYPE_FileHash = 511
RCD_TYPE_Geolocation = 520
RCD_TYPE_FilePolicy = 530
RCD_TYPE_SSLPolicy = 600
RCD_TYPE_SSLCipher = 602
RCD_TYPE_SSLVersion = 604
RCD_TYPE_SSLCertificateStatus = 605
RCD_TYPE_SSLActualAction = 606
RCD_TYPE_SSLExpectedAction = 607
RCD_TYPE_SSLFlowStatus = 608
RCD_TYPE_SSLURLCategory = 613
RCD_TYPE_SSLCertificate = 614
RCD_TYPE_NetworkAnalysis = 700


class Error(Exception): pass
class IPAddressError(Error): pass

basedir = os.path.dirname(os.path.realpath(__file__)) + '/'

def test_bit(comp_bits, check_bit):
    return comp_bits & 1 << check_bit != 0

def get_addr(bits):
    hi = bits >> 64
    lo = bits & ((1 << 64) - 1)
    if hi != 0:
        try:
            return socket.inet_ntop(socket.AF_INET6, struct.pack('!2Q', hi, lo))
        except socket.error:
            raise IPAddressError('Invalid IP specified')
    else:
        try:
            bits = bits & 0xffffffff
            return socket.inet_ntop(socket.AF_INET, struct.pack('!I', bits))
        except socket.error:
            raise IPAddressError('Invalid IP specified')

class LoadParsers(object):

    def __init__(self, caller, plugin_dir=basedir):
        self.basedir = basedir
        self.instance_dict = {}
        self.caller = caller

    def load_from(self, load_type, load_string):
        def isNotClass(element):
            return not isinstance(element, type)
        self.__load_iters([member for member in inspect.getmembers(self.caller, isNotClass)], load_type, load_string)

    def __load_iters(self, iterobjs, load_type, load_string):
        for k,v in iterobjs:
            if not isinstance(v, type) and k.startswith(load_string):
                clsname = k[len(load_string):]
                if load_type == 'vars':
                    mod_name = clsname.lower()
                    cls_instance = self.__do_load(mod_name, clsname)
                else:
                    cls_instance = getattr(self.caller, clsname, None)
                if cls_instance is not None:
                    self.instance_dict[v] = cls_instance

    def __do_load(self, modname, clsname):
        mod_name = os.path.basename(modname.rsplit('.', 1)[0])
        mod_fh = None
        glbls = globals()
        try:
            loaded = __import__(mod_name, glbls, level=1)
            return getattr(loaded, clsname)
        except (ImportError, AttributeError) as e: 
            return None

