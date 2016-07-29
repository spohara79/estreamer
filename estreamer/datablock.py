from base import Struct
import struct

class DataBlock(Struct):

    __sub_length__ = 8
    ''' 
    we use the __hide_data__ as a hack.. to prevent the 'data' field from being populated with
    the remaining buffer when parsing a structure at arbitrary places inside another Struct 
    '''
    __hide_data__ = True

    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('string', 'variable', 0),
    ]

class BlobDataBlock(DataBlock): pass
class StringDataBlock(DataBlock): pass

class UUIDDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 14),
        ('length', 'uint32', 0),
        ('uuid', 'uint8[16]', 0),
        ('string_type', 'uint32', 0),
        ('string_len', 'uint32', 0)
    ]

class AccessControlMetadataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 15),
        ('length', 'uint32', 0),
        ('rev', 'uint8[16]', 0),
        ('rule_id', 'uint32', 0),
        ('string_type', 'uint32', 0),
        ('string_len', 'uint32', 0)
    ]

class ICMPTypeDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 19),
        ('length', 'uint32', 0),
        ('icmp_type', 'uint16', 0),
        ('protocol', 'uint16', 0),
        ('description', StringDataBlock, 0),
    ]

class ICMPCodeDataBlock(Struct):
    _fields_ = [
        ('block_type', 'uint32', 20),
        ('block_length', 'uint32', 0),
        ('code', 'uint16', 0),
        ('type', 'uint16', 0),
        ('protocol', 'uint16', 0),
        ('description', StringDataBlock, 0),
    ]

class AccessControlReasonDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 21),
        ('length', 'uint32', 0),
        ('reason', 'uint16', 0),
        ('string_type', 'uint32', 0),
        ('string_len', 'uint32', 0)
    ]

class IPReputationDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 21),
        ('length', 'uint32', 0),
        ('policy_uuid', 'uint16', 0),
        ('string_type', 'uint32', 0),
        ('string_len', 'uint32', 0)
    ]

class FileEventDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 21),
        ('length', 'uint32', 0),
        ('device_id', 'uint32', 0),
        ('con_instance', 'uint16', 0),
        ('con_counter', 'uint16', 0),
        ('con_ts', 'uint32', 0),
        ('event_ts', 'uint32', 0),
        ('src_ip', 'uint8[16]', 0),
        ('dst_ip', 'uint8[16]', 0),
        ('disposition', 'uint8', 0),
        ('spero', 'uint8', 0),
        ('storage', 'uint8', 0),
        ('analysis_status', 'uint8', 0),
        ('archive_status', 'uint8', 0),
        ('threat_score', 'uint8', 0),
        ('action', 'uint8', 0),
        ('hash', 'uint8[32]', 0),
        ('file_id', 'uint32', 0),
        ('file_name', StringDataBlock, 0),
        ('file_size', 'uint64', 0),
        ('direction', 'uint8', 0),
        ('app_id', 'uint32', 0),
        ('user_id', 'uint32', 0),
        ('uri', StringDataBlock, 0),
        ('signature', StringDataBlock, 0),
        ('src_port', 'uint16', 0),
        ('dst_port', 'uint16', 0),
        ('proto', 'uint8', 6),
        ('policy_uuid', 'uint8[16]', 0),
        ('src_country', 'uint16', 0),
        ('dst_country', 'uint16', 0),
        ('web_app_id', 'uint32', 0),
        ('client_app_id', 'uint32', 0),
        ('security_context', 'uint8[16]', 0),
        ('ssl_cert_fingerprint', 'uint8[20]', 0),
        ('ssl_action', 'uint16', 0),
        ('ssl_flow_status', 'uint16', 0),
        ('archive_hash', StringDataBlock, 0),
        ('archive_name', StringDataBlock, 0),
        ('archive_depth', 'uint8', 0),
    ]

class MalwareEventDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 47),
        ('length', 'uint32', 0),
        ('agent_uuid', 'uint8[16]', 0),
        ('cloud_uuid', 'uint8[16]', 0),
        ('event_ts', 'uint32', 0),
        ('event_type_id', 'uint32', 0),
        ('event_sub_id', 'uint32', 0),
        ('detector_id', 'uint8', 0),
        ('detect_name', StringDataBlock, 0),
        ('user', StringDataBlock, 0),
        ('file_name', StringDataBlock, 0),
        ('file_path', StringDataBlock, 0),
        ('file_hash', StringDataBlock, 0),
        ('file_size', 'uint32', 0),
        ('file_type', 'uint32', 0),
        ('file_ts', 'uint32', 0),
        ('parent_file', StringDataBlock, 0),
        ('parent_file_hash', StringDataBlock, 0),
        ('event_desc', StringDataBlock, 0),
        ('device_id', 'uint32', 0),
        ('con_instance', 'uint16', 0),
        ('con_counter', 'uint16', 0),
        ('con_event_ts', 'uint32', 0),
        ('direction', 'uint8', 0),
        ('src_ip', 'uint8[16]', 0),
        ('dst_ip', 'uint8[16]', 0),
        ('app_id', 'uint32', 0),
        ('user_id', 'uint32', 0),
        ('policy_uuid', 'uint8[16]', 0),
        ('disposition', 'uint8', 0),
        ('retro_disposition', 'uint8', 0),
        ('uri', StringDataBlock, 0),
        ('src_port', 'uint16', 0),
        ('dst_port', 'uint16', 0),
        ('src_country', 'uint16', 0),
        ('dst_country', 'uint16', 0),
        ('web_app_id', 'uint32', 0),
        ('client_app_id', 'uint32', 0),
        ('action', 'uint8', 0),
        ('proto', 'uint8', 6),
        ('threat_score', 'uint8', 0),
        ('ioc_number', 'uint16', 0),
        ('security_context', 'uint8[16]', 0),
        ('ssl_cert_fingerprint', 'uint8[20]', 0),
        ('ssl_action', 'uint16', 0),
        ('ssl_flow_status', 'uint16', 0),
        ('archive_hash', StringDataBlock, 0),
        ('archive_name', StringDataBlock, 0),
        ('archive_depth', 'uint8', 0),
    ]

class FileEventHashDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('hash', 'uint8[32]', 0),
        ('file_name', StringDataBlock, 0),
        ('disposition', 'uint8', 0),
        ('user_defined', 'uint8', 0),
    ]

class FileTypeIDMetadata(Struct):
    _fields_ = [
        ('id', 'uint32', 0),
        ('file_type_name', StringDataBlock, 0),
    ]
class RuleDocumentationDataBlock(Struct):
    _fields_ = [
        ('type', 'uint32', 27),
        ('length', 'uint32', 8),
        ('sig_id', 'uint32', 0),
        ('gen_id', 'uint32', 0),
        ('rev', 'uint32', 0),
        ('summary', StringDataBlock, 0),
        ('impact', StringDataBlock, 0),
        ('info', StringDataBlock, 0),
        ('affected', StringDataBlock, 0),
        ('attack_scenarios', StringDataBlock, 0),
        ('false_pos', StringDataBlock, 0),
        ('false_neg', StringDataBlock, 0),
        ('corrective_action', StringDataBlock, 0),
        ('contributors', StringDataBlock, 0),
        ('references', StringDataBlock, 0),
    ]

class GeolocationDataBlock(Struct):

    _fields_ = [
        ('type', 'uint32', 0),
        ('length', 'uint32', 0),
        ('cc', 'uint16', 0),
        ('country_name', StringDataBlock, 0),
    ]

