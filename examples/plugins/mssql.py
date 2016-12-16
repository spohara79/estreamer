from estreamer import plugin
from estreamer import base
from estreamer import config
import os
import errno
import pymssql
import binascii
import time
import ConfigParser


class MSSQLPlugin(plugin.Plugin):
    ''' Writes Connection Statitic data to MS SQL database '''

    __info__ = {
        'description': 'MSSQL writer',
        'author': "Ted Papaioannou",
        'version': '0.1',
        'callback': 'process_record',
    }

    def __init__(self, *args, **kwargs):
        plugin.Plugin.__init__(self, *args, **kwargs)
        self.users = {}
        self.url_categories = {}
        self.cfg = ConfigParser.ConfigParser()
        self.cfg.read('estreamer.config')

    def parse_record(self, evt_data):
        event = None
        if evt_data.type == config.RCD_TYPE_UserMeta:
            # For some reason there is a null byte after the 
            # username in the data
            self.users[evt_data.data.user_id] = evt_data.data.username.string.strip('\x00')
        
        elif evt_data.type == config.RCD_TYPE_URLCategory:
            self.url_categories[evt_data.data.category_id] = evt_data.data.name
            
        elif evt_data.type == config.RCD_TYPE_Connection:
            evt = evt_data.data

            if evt.user_id not in [0,9999999] \
                and evt.url_category != 0 \
                and evt.last_pkt_time != 0:
                try:
                    event = (config.get_addr(evt.initiator_ip), \
                            config.get_addr(evt.responder_ip), \
                            evt.initiator_port, evt.responder_port, \
                            evt.first_pkt_time, evt.last_pkt_time, \
                            evt.initiator_tx_pkts, evt.resp_tx_pkts, \
                            evt.initiator_tx_bytes, evt.resp_tx_bytes, \
                            evt.user_id, evt.url_category, \
                            evt.client_url.string, evt.conn_counter, \
                            self.url_categories[evt.url_category], \
                            self.users[evt.user_id])

                    return event
                except KeyError as exc:
                    raise exc

        return event

        
    def process_record(self, record):
        # Collect all events in a list for bulk SQL insert
        events = []

        # check if it's a bundle.  loop through messages
        if record.type == config.MSG_TYPE_MessageBundle:
            msg_bundle = record.data
            for evt_data in msg_bundle.data:
                event = self.parse_record(evt_data)
                if event:
                    events.append(event)

        # otherwise, it's a single message
        else:
            event = self.parse_record(evt_data)
            if event:
                events.append(event)


        if events:
            
            with pymssql.connect(self.cfg.get('ms_sql','hostname'), \
                    self.cfg.get('ms_sql','user'), self.cfg.get('ms_sql','password'), \
                    self.cfg.get('ms_sql','db')) \
                    as conn:
                cursor = conn.cursor()
                query = ("INSERT INTO " + self.cfg.get('ms_sql','table') + "("
                        "initiatorIp, responderIp, initiatorPort, "
                        "responderPort, firstPktsecond, lastPktsecond, "
                        "initiatorPkts, responderPkts, initiatorBytes, "
                        "responderBytes, userId, urlCategory, url, "
                        "connectId, urlCategoryName, username) "
                        "VALUES(%s, %s, %d, %d, %d, %d, %d, %d, %d, %d, %d, "
                        "%s, %d, %d, %s, %s) "
                        )
                try:
                    cursor.executemany(query, events)
                    conn.commit()
                except pymssql.IntegrityError:
                    # Unique key exists on (firstPktsecond, connectId, 
                    # userID) however a trigger would be a better 
                    # solution for performance
                    # Duplicate record possibly because using 
                    # firstPktsecond instead of timestamp
                    #print 'Duplicate record'
                    pass
                except Exception as e:  
                    pass

