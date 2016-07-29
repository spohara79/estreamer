# local libs
import config
from datablock import *
from base import Struct, UnpackError

# std libs
import struct


# which record types use the archival stamp
ARCHIVAL_RCD_TYPES = [2, 400, 9, 110, 111, 112, 125, 207, 208]

# record types we will handle
RCD_TYPE_Packet = 2
RCD_TYPE_Priority = 4
RCD_TYPE_Impact = 9
RCD_TYPE_ClientApp = 55
RCD_TYPE_User = 62
RCD_TYPE_Server = 63
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

class Packet(Struct):

    _fields_ = [
        ('device_id', 'uint32', 0),
        ('event_id', 'uint32', 0),
        ('event_second', 'uint32', 0),
        ('packet_second', 'uint32', 0),
        ('packet_microsecond', 'uint32', 0),
        ('link_type', 'uint32', 0),
        ('length', 'uint32', 0),
    ]

class Priority(Struct):

    _fields_ = [
        ('priority_id', 'uint32', 0),
        ('length', 'uint16', 0),
    ]

class IntrusionEvent(Struct):

    _fields_ = [
        ('type', 'uint32', 45),
        ('length', 'uint32', 0),
        ('dev_id', 'uint32', 0),
        ('event_id', 'uint32', 0),
        ('event_sec', 'uint32', 0),
        ('event_msec', 'uint32', 0),
        ('rule_id', 'uint32', 0),
        ('gen_id', 'uint32', 0),
        ('rule_rev', 'uint32', 0),
        ('class_id', 'uint32', 0),
        ('priority_id', 'uint32', 0),
        ('src_ip', 'uint8[16]', 0),
        ('dst_ip', 'uint8[16]', 0),
        ('src_port', 'uint16', 0),
        ('dst_port', 'uint16', 0),
        ('ip_proto', 'uint8', 0),
        ('impact_flags', 'uint8', 0),
        ('impact', 'uint8', 0),
        ('blocked', 'uint8', 0),
        ('mpls', 'uint32', 0),
        ('vlan_id', 'uint16', 0),
        ('pad', 'uint16', 0),
        ('policy_uuid', 'uint8[16]', 0),
        ('user_id', 'uint32', 0),
        ('web_app_id', 'uint32', 0),
        ('client_app_id', 'uint32', 0),
        ('app_proto_id', 'uint32', 0),
        ('access_rule_id', 'uint16', 0),
        ('access_policy_uuid', 'uint8[16]', 0),
        ('ingress_int_uuid', 'uint8[16]', 0),
        ('egress_int_uuid', 'uint8[16]', 0),
        ('ingress_zone_uuid', 'uint8[16]', 0),
        ('egress_zone_uuid', 'uint8[16]', 0),
        ('conn_stamp', 'uint16', 0),
        ('conn_id', 'uint16', 0),
        ('conn_counter', 'uint16', 0),
        ('src_country', 'uint16', 0),
        ('dst_country', 'uint16', 0),
        ('ioc_num', 'uint16', 0),
        ('security_context', 'uint8[16]', 0),
        ('ssl_cert_fingerprint', 'uint8[20]', 0),
        ('ssl_action', 'uint16', 0),
        ('ssl_flow_status', 'uint16', 0),
        ('analysis_policy_uuid', 'uint8[16]', 0),
    ]

class Impact(Struct):

    _fields_ = [
        ('type', 'uint32', 20),
        ('length', 'uint32', 0),
        ('event_id', 'uint32', 0),
        ('device_id', 'uint32', 0),
        ('event_sec', 'uint32', 0),
        ('impact_flags', 'uint8', 0),
        ('src_ip', 'uint8[16]', 0),
        ('dst_ip', 'uint8[16]', 0),
        ('description', StringDataBlock, 0)
    ]



class ClientApp(Struct):

    _fields_ = [
        ('app_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class User(Struct):

    _fields_ = [
        ('user_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class Server(Struct):

    _fields_ = [
        ('app_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class RuleMeta(Struct):

    _fields_ = [
        ('generator_id', 'uint32', 0),
        ('rule_id', 'uint32', 0),
        ('rule_rev', 'uint32', 0),
        ('signature_id', 'uint32', 0),
        ('length', 'uint16', 0),
        ('uuid', 'uint8[16]', 0),
        ('rev_uuid', 'uint8[16]', 0),
    ]

class Classification(Struct):

    _fields_ = [
        ('classification_policy_id', 'uint32', 0),
        ('name_length', 'uint16', 0),
        ('name', 'variable', 0),
        ('description_length', 'uint16', 0),
        ('description', 'variable', 0),
        ('uuid', 'uint8[16]', 0),
        ('uuid_rev', 'uint8[16]', 0),
    ]

class CorrelationPolicy(Struct):

    _fields_ = [
        ('correlation_policy_id', 'uint32', 0),
        ('name_length', 'uint16', 0),
        ('name', 'variable', 0),
        ('description_length', 'uint16', 0),
        ('description', 'variable', 0),
        ('uuid', 'uint8[16]', 0),
        ('uuid_rev', 'uint8[16]', 0),
    ]

class CorrelationRule(Struct):

    _fields_ = [
        ('correlation_rule_id', 'uint32', 0),
        ('name_length', 'uint16', 0),
        ('name', 'variable', 0),
        ('description_length', 'uint16', 0),
        ('description', 'variable', 0),
        ('event_length', 'uint16', 0),
        ('event', 'variable', 0),
        ('uuid', 'uint8[16]', 0),
        ('uuid_rev', 'uint8[16]', 0),
        ('whitelist_uuid', 'uint8[16]', 0),
    ]

class ExtraData(Struct):

    _fields_ = [
        ('data_block_type', 'uint32', 4),
        ('data_block_length', 'uint32', 0),
        ('device_id', 'uint32', 0),
        ('event_id', 'uint32', 0),
        ('event_sec', 'uint32', 0),
        ('type', 'uint32', 0),
        ('blob_block', BlobDataBlock, 0),
    ]

class ExtraMeta(Struct):

    _fields_ = [
        ('data_block_type', 'uint32', 0), 
        ('data_block_length', 'uint32', 0),
        ('type', 'uint32', 0),
        ('name', StringDataBlock, 0),
        ('encoding', StringDataBlock, 0),
    ]

class CorrelationEvent(Struct):

    _fields_ = [
        ('block_type', 'uint32', 156),
        ('block_length', 'uint32', 0),
        ('device_id', 'uint32', 0),
        ('correlation_event_sec', 'uint32', 0),
        ('event_id', 'uint32', 0),
        ('policy_id', 'uint32', 0),
        ('rule_id', 'uint32', 0),
        ('priority', 'uint32', 0),
        ('description', StringDataBlock, 0),
        ('event_type', 'uint8', 0),
        ('event_device_id', 'uint32', 0),
        ('signature_id', 'uint32', 0),
        ('signature_gen_id', 'uint32', 0),
        ('trigger_event_sec', 'uint32', 0),
        ('trigger_event_id', 'uint32', 0),
        ('event_defined_mask', 'uint32', 0),
        ('impact_flags', 'uint8', 0),
        ('ip_protocol', 'uint8', 0),
        ('network_protocol', 'uint16', 0),
        ('src_addr', 'uint8[4]', 0),
        ('src_host_type', 'uint8', 0),
        ('src_vlan_id', 'uint16', 0),
        ('src_os_fingerprint_id', 'uint8[16]', 0),
        ('src_criticality', 'uint16', 0),
        ('src_user_id', 'uint32', 0),
        ('src_port', 'uint16', 0),
        ('src_server_id', 'uint32', 0),
        ('dst_addr', 'uint8[4]', 0),
        ('dst_host_type', 'uint8', 0),
        ('dst_vlan_id', 'uint16', 0),    
        ('dst_os_fingerprint_id', 'uint8[16]', 0),
        ('dst_criticality', 'uint16', 0),
        ('dst_user_id', 'uint32', 0),
        ('dst_port', 'uint16', 0),
        ('dst_server_id', 'uint32', 0),
        ('blocked', 'uint8', 0),
        ('ingress_int_uuid','uint8[16]', 0),
        ('egress_int_uuid', 'uint8[16]', 0),
        ('ingress_zone_uuid','uint8[16]', 0),
        ('egress_zone_uuid', 'uint8[16]', 0),
        ('src_addr_v6', 'uint8[16]', 0),
        ('dst_addr_v6', 'uint8[16]', 0),
        ('src_country', 'uint16', 0),
        ('dst_country', 'uint16', 0),
        ('sec_intel_uuid', 'uint8[16]', 0),
        ('security_context','uint8[16]', 0),
        ('ssl_policy_id', 'uint8[16]', 0),
        ('ssl_action', 'uint32', 0),
    ]

class SecurityZone(Struct):

    _fields_ = [
        ('block_type', 'uint32', 14),
        ('block_length', 'uint32', 0),
        ('sec_zone_uuid', 'uint8[16]', 0),
        ('sec_zone_name', StringDataBlock, 0),
    ]

class InterfaceName(Struct):

    _fields_ = [
        ('block_type', 'uint32', 14),
        ('block_length', 'uint32', 0),
        ('interface_uuid', 'uint8[16]', 0),
        ('interface_name', StringDataBlock, 0),
    ]

class AcessControlPolicy(Struct):

    _fields_ = [
        ('block_type', 'uint32', 14),
        ('block_length', 'uint32', 0),
        ('policy_uuid', 'uint8[16]', 0),
        ('policy_name', StringDataBlock, 0),
    ]

class IntrusionPolicy(Struct):

    _fields_ = [
        ('block_type', 'uint32', 14),
        ('block_length', 'uint32', 0),
        ('policy_uuid', 'uint8[16]', 0),
        ('policy_name', StringDataBlock, 0),
    ]

class AccessControlRuleID(Struct):

    _fields_ = [
        ('block_type', 'uint32', 14),
        ('block_length', 'uint32', 0),
        ('rule_uuid', 'uint8[16]', 0),
        ('rule_id', 'uint32', 0),
        ('rule_name', StringDataBlock, 0),
    ]

class AccessControlRuleAction(Struct):

    _fields_ = [
        ('action_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class URLCategory(Struct):

    _fields_ = [
        ('category_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class URLReputation(Struct):

    _fields_ = [
        ('reputation_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class ManagedDevice(Struct):

    _fields_ = [
        ('action_id', 'uint32', 0),
        ('length', 'uint32', 0),
        ('name', 'variable', 0),
    ]

class MalwareEvent(MalwareEventDataBlock): pass


class SecurityIntel(Struct):

    _fields_ = [
        ('data_block', 'uint32', 0),
        ('length', 'uint32', 0),
        ('intel_uuid', 'uint8[16]', 0),
        ('intel_name', StringDataBlock, 0)
    ]

class MalwareEventTypeMeta(Struct):

    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('event_type', 'variable', 0),
    ]

class MalwareEventSubTypeMeta(Struct):

    _fields_ = [
        ('subtype', 'uint32', 0),
        ('length', 'uint32', 0),
        ('event_subtype', 'variable', 0),
    ]

class FireAMPDetector(Struct):

    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('detector_type', 'variable', 0),
    ]

class FireAMPFile(Struct):

    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('file_type', 'variable', 0),
    ]

class SecurityContext(Struct):

    _fields_ = [
        ('context_uuid', 'uint8[16]', 0),
        ('context_name', 'variable', 0),
    ]

class ICMPType(ICMPTypeDataBlock): pass
class ICMPCode(ICMPCodeDataBlock): pass

class IntrusionEvent(Struct):

    _fields_ = [
        ('block_type', 'uint32', 0),
        ('block_length', 'uint32', 0),
        ('device_id', 'uint32', 0),
        ('event_id', 'uint32', 0),
        ('event_sec', 'uint32', 0),
        ('event_microsec', 'uint32', 0),
        ('signature_id', 'uint32', 0),
        ('signature_gen_id', 'uint32', 0),
        ('signature_rev', 'uint32', 0),
        ('priority', 'uint32', 0),
        ('src_ip', 'uint8[16]', 0),
        ('dst_ip', 'uint8[16]', 0),
        ('src_port', 'uint16', 0),
        ('dst_port', 'uint16', 0),
        ('ip_protocol', 'uint8', 0),
        ('impact_flags', 'uint8', 0),
        ('impact', 'uint8', 0),
        ('blocked', 'uint8', 0),
        ('mpls_label', 'uint32', 0),
        ('vlan_id', 'uint16', 0),
        ('padding', 'uint16', 0),
        ('policy_uuid', 'uint8[16]', 0),
        ('user_id', 'uint32', 0),
        ('webapp_id', 'uint32', 0),
        ('client_app_id', 'uint32', 0),
        ('app_proto_id', 'uint32', 0),
        ('access_control_rule', 'uint32', 0),
        ('access_control_policy', 'uint8[16]', 0),
        ('ingress_int_uuid','uint8[16]', 0),
        ('egress_int_uuid', 'uint8[16]', 0),
        ('ingress_zone_uuid','uint8[16]', 0),
        ('egress_zone_uuid', 'uint8[16]', 0),
        ('conn_ts', 'uint32', 0),
        ('conn_instance', 'uint16', 0),
        ('conn_counter', 'uint16', 0),
        ('src_country', 'uint16', 0),
        ('dst_country', 'uint16', 0),
        ('ioc_number', 'uint16', 0),
        ('security_context','uint8[16]', 0),
        ('ssl_fingerprint', 'uint8[20]', 0),
        ('ssl_action', 'uint16', 0),
    ]

class FileEvent(FileEventDataBlock): pass
class FileEvent2(FileEventDataBlock): pass
class RuleDocumentation(RuleDocumentationDataBlock): pass
class FileHash(FileEventHashDataBlock): pass
class Geolocation(GeolocationDataBlock): pass

class FilePolicy(Struct):

    _fields_ = [
        #('policy_uuid', 'uint8[16]', 0),
        ('policy_uuid', 'uint8[24]', 0),
        ('policy_name', StringDataBlock, 0),
    ]

class SSLPolicy(Struct):

    #_fields_ = [
    #    ('policy_uuid', 'uint8[16]', 0),
    #    ('policy_name', StringDataBlock, 0),
    #]
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('description', 'variable', 0),
    ]

class SSLCipher(Struct):

    #_fields_ = [
    #    ('cipher_id', 'uint32', 0),
    #    ('cipher_name', StringDataBlock, 0),
    #]
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('description', 'variable', 0),
    ]

class SSLVersion(Struct):

    #_fields_ = [
    #    ('ssl_version', 'uint32', 0),
    #    ('ssl_version_name', StringDataBlock, 0),
    #]
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('description', 'variable', 0),
    ]

class SSLCertificateStatus(Struct):

    _fields_ = [
        ('cert_status_id', 'uint32', 0),
        ('cert_status', StringDataBlock, 0),
    ]

class SSLActualAction(Struct):

    #_fields_ = [
    #    ('action_id', 'uint32', 0),
    #    ('action', StringDataBlock, 0),
    #]
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('description', 'variable', 0),
    ]

class SSLExpectedAction(Struct):

    #_fields_ = [
    #    ('action_id', 'uint32', 0),
    #    ('expected_action', StringDataBlock, 0),
    #]
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('description', 'variable', 0),
    ]

class SSLFlowStatus(Struct):

    #_fields_ = [
    #    ('status_id', 'uint32', 0),
    #    ('status_description', StringDataBlock, 0),
    #]
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('description', 'variable', 0),
    ]

class SSLURLCategory(Struct):

    _fields_ = [
        ('category_id', 'uint32', 0),
        ('category_description', StringDataBlock, 0),
    ]

class SSLCertificate(Struct):

    _fields_ = [
        ('type', 'uint32', 50),
        ('length', 'uint32', 0),
        ('fingerprint_hash', 'uint8[20]', 0),
        ('pubkey_hash', 'uint8[20]', 0),
        ('serial_number', 'uint8[20]', 0),
        ('serial_length', 'uint32', 0),
        ('subject_cn', StringDataBlock, 0),
        ('subject_org', StringDataBlock, 0),
        ('subject_ou', StringDataBlock, 0),
        ('subject_cc', StringDataBlock, 0),
        ('issuer_cn', StringDataBlock, 0),
        ('issuer_org', StringDataBlock, 0),
        ('issuer_ou', StringDataBlock, 0),
        ('issuer_cc', StringDataBlock, 0),
        ('validity_start', 'uint32', 0),
        ('validity_end', 'uint32', 0),
    ]

class NetworkAnalysis(Struct):

    _fields_ = [
        ('policy_uuid', 'uint8[16]', 0),
        ('policy_name', StringDataBlock, 0),
    ]

class EventDataError(Exception): pass

class EventData(Struct):

    ''' start fields for metaclass parsing '''
    __load_parsers__ = {
        'load_type': 'class',
        'load_string': 'RCD_TYPE_',
    }

    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
    ]

    ''' end metaclass parsing fields '''

    __parsers__ = {}

    def __init__(self, *args, **kwargs):
        if args:
            self.type = struct.unpack('>I', args[0][:4])[0]
            # check if it's  an event data record that uses archival timestamps and if we've set archival
            if self.type in ARCHIVAL_RCD_TYPES and config.test_bit(Struct.get_flags(), 23) and 'reserved' not in self._field_names_:
                self._fields_.extend([('timestamp', 'uint32', 0), ('reserved', 'uint32', 0)])
                self._field_names_.extend(['timestamp', 'reserved'])
                self._field_format_.update({'timestamp': 'I', 'reserved': 'I'})
                super(EventData, self).__init__(*args, **kwargs)
            else:
                super(EventData, self).__init__(*args, **kwargs)
            self._unpack_data()

    def _unpack_data(self):
        try:
            self.data = self.__parsers__[self.type](self.data)
        except (KeyError, UnpackError):
            pass
