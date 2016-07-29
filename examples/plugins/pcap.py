from estreamer import plugin
from estreamer import base
from estreamer import config
import os
import errno

class PcapPlugin(plugin.Plugin):
    __info__ = {
        'description': 'pcap writer',
        'author': "Sean O'Hara",
        'version': '0.1',
        'callback': 'parse_record',
    }

    __pcap_dir__ = os.path.dirname(os.path.realpath(__file__)) + '/pcap/'

    def __init__(self, *args, **kwargs):
        #super(PcapPlugin, self).__init__(*args, **kwargs)
        plugin.Plugin.__init__(self, *args, **kwargs)
        try:
            os.makedirs(self.__pcap_dir__)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise

    '''
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    '''
    class GlobalHeader(base.Struct):
        _fields_ = [
            ('magic_number', 'uint32', 0xa1b2c3d4), # magic number
            ('version_major', 'uint16', 2),         # major version number
            ('version_minor', 'uint16', 4),         # minor version number
            ('thiszone', 'int32', 0),               # GMT to local correction
            ('sigfigs', 'uint32', 0),               # accuracy of timestamps
            ('snaplen', 'uint32', 0x1ffff),         # max length of captured packets, in octets
            ('network', 'uint32', 1),               # data link type
        ]

    class RecordHeader(base.Struct):
        _fields_ = [
            ('ts_sec', 'uint32', 0),   # timestamp seconds
            ('ts_usec', 'uint32', 0),  # timestamp microseconds
            ('incl_len', 'uint32', 0), # number of octets of packet
            ('orig_len', 'uint32', 0), # actual length of packet
        ]

    def write_pcap(self, name, _struct):
        with open(self.__pcap_dir__ + name, 'wb') as f:
            f.write(self.GlobalHeader().pack())
            f.write(self.RecordHeader(
                ts_sec=_struct.packet_second,
                ts_usec=_struct.packet_microsecond,
                incl_len=_struct.length,
                orig_len=_struct.length
            ).pack())
            f.write(_struct.data)

    def parse_record(self, record):
        # check if it's a bundle.  loop through messages to check if it's a packet
        if record.type == config.MSG_TYPE_MessageBundle:
            msg_bundle = record.data
            for evt_data in msg_bundle.data:
                # make sure it's a packet
                if evt_data.type == config.RCD_TYPE_Packet:
                    pcap_struct = evt_data.data
                    pcap_name = 'pcap_{}_{}'.format(pcap_struct.event_id, evt_data.timestamp)
                    self.write_pcap(pcap_name, pcap_struct)
        # otherwise, it's a single message
        else:
            evt_data = record.data.data
            if evt_data.type == config.RCD_TYPE_Packet:
                pcap_struct = evt_data.data
                pcap_name = 'pcap_{}_{}'.format(pcap_struct.event_id, evt_data.timestamp)
                self.write_pcap(pcap_name, pcap_struct)
