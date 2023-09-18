import os
import sys
import glob
import signal
import argparse
import logging
import time
import math
import struct
# Add BF Python to search path
bfrt_location = '{}/lib/python*/site-packages/tofino'.format(
    os.environ['SDE_INSTALL'])
sys.path.append(glob.glob(bfrt_location)[0])
import bfrt_grpc.client as gc
from bfrt_grpc.client import BfruntimeRpcException

def hex_to_ip(hex_ip):
    bin_str = bin(hex_ip)
    length = len(bin_str)
    while (length < 34):
        bin_str = bin_str[0:2] + '0' + bin_str[2:]
        length += 1
    ip = "%d.%d.%d.%d" % (int(bin_str[2:10], 2), int(bin_str[10:18], 2), int(bin_str[18:26], 2), int(bin_str[26:34], 2))
    return ip

swports = [142,141,192]
EGRESS_PORT_INVALID = 511
class Table(object):
    def __init__(self, target, gc, bfrt_info, table_name, pipe):
        self.log = logging.getLogger(__name__)
        self.target = target
        self.table_name = "%s.%s"%(pipe,table_name)
        self.gc = gc

        self.table = bfrt_info.table_get(table_name)
        self.mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
        self.entry = []
        self.mirror_session_id = []
    def readTable_tbl(self):
        # 如果带寄存器的话Apply table operations to sync the direct registers
        # target_table.operations_execute(self.target, 'SyncRegisters')
        resp = self.table.entry_get(self.target, None, {"from_hw": True})#read all entry in table
        resp2 = self.table.entry_get(self.target, None, {"from_hw": True})
        length = len(list(resp2))
        print("\nR---->Table: %s, %d entry"%(self.table_name,length))
        for data,key in resp:
            print(key)
            print(data)
        print()
    def readTable_reg(self):
        #"Syncing indirect stful registers"
        self.table.operations_execute(self.target, 'Sync')
        resp = self.table.entry_get(self.target, None, {"from_hw": False})#read all entry in table
        resp2 = self.table.entry_get(self.target, None, {"from_hw": False})
        length = len(list(resp2))
        print("\nR---->Register: %s, %d entry"%(self.table_name,length))
        for data,key in resp:
            print(key)
            print(data)
        print()
    def clearEntry(self):
        self.table.entry_del(self.target)
        self.entry = []
        self.log.info('Clear entry of table: {}'.format(self.table_name))
        print("\nC---->Table %s is empty now!"%self.table_name)
    def initRegister(self,value=0,reg_field="f1"):
        resp2 = self.table.entry_get(self.target, None, {"from_hw": False})
        length = len(list(resp2))
        for i in range(length):
            self.writeRegister(i,value,reg_field)
        self.log.info('Init register {}(length: {}) all to 0'.format(self.table_name,length))
        print("\nW---->Init register {}(length: {}) all to 0:".format(self.table_name,length))
    def writeRegister(self,index,value,reg_field="f1"):
        resp = self.table.entry_mod(
            self.target,
            [self.table.make_key([self.gc.KeyTuple('$REGISTER_INDEX', index)])],
            [self.table.make_data([self.gc.DataTuple('%s.%s'%(self.table_name,reg_field), value)])]
            )
    def readRegister(self,index,reg_field="f1", silence=False):
        resp = self.table.entry_get(
            self.target,
            [self.table.make_key([self.gc.KeyTuple('$REGISTER_INDEX', index)])],
            {"from_hw": True}
            )
        data_dict = next(resp)[0].to_dict()
        #if(silence == False):
            #print(data_dict["%s.%s"%(self.table_name,reg_field)][1], end='\t')
        return data_dict["%s.%s"%(self.table_name,reg_field)][1]
    def readDirectRegister(self,match_type,key):
        key_list = self.__getKeyList__(match_type,key)
        resp = register_dir_table.entry_get(
            self.target,
            key_list,
            {"from_hw": True})
        data_dict = next(resp)[0].to_dict()
        print(data_dict["%s.f1"%self.table_name][1], end='\t')
    def key_field_annotation_add(keys):
        for key, alias in keys:
            self.table.info.key_field_annotation_add(key, alias)
    def __getKeyList__(self,match_type,keys):
        entry_keys = []
        for key in keys:
                if(match_type == "exact"):
                    # self.table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
                    #print(keys[0][0])
                    self.table.info.key_field_annotation_add(keys[0][0], "bytes")
                    #self.table.info.key_field_annotation_add("ig_md.md_ddos.dst_cnt3", "bytes")
                    #self.table.info.key_field_annotation_add("ig_md.md_ddos.src2_cnt3", "bytes")
                    #self.table.info.key_field_annotation_add("ig_md.md_ddos.src2_cnt3", "bytes")
                    #self.table.info.key_field_annotation_add("ig_md.md_ddos.src_cnt3", "int")
                    # self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1]))
                elif(match_type == "lpm"):
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1],prefix_len=key[2]))
                elif(match_type == "ternary"):
                    self.table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1],key[2]))
                elif(match_type == "range"):
                    self.table.info.key_field_annotation_add("hdr.ipv4.dst_addr[15:0]", "ipv4")
                    entry_keys.append(self.gc.KeyTuple(key[0], low=key[1],high=key[2]))
                elif(match_type == "exact-none"):
                    entry_keys.append(self.gc.KeyTuple(key[0],key[1]))
        key_list = [self.table.make_key(entry_keys)]
        return key_list
    def addEntry(self,match_type,keys,action,action_parameter):

        if(self.entry.count(keys) == 1):
            print("Entry already exist, won't insert twice!")
            self.log.info("%s :Entry already exist, won't insert twice!"%self.table_name)
        else:
            key_list = self.__getKeyList__(match_type,keys)
            entry_data = []
            for parameter in action_parameter:
                entry_data.append(self.gc.DataTuple(parameter[0],parameter[1]))
            action = "SwitchIngress.%s"%action
            data_list = [self.table.make_data(entry_data,action)]
            try:
                resp = self.table.entry_get(self.target,key_list,{"from_hw": True})
                data_dict = next(resp)[0].to_dict()
            except:
                print("\nA---->Add entry(%s): %s %s(%s)"%(match_type,keys,action,action_parameter))
                self.table.entry_add(self.target, key_list, data_list)
                self.log.info("Added entry success: %s"%self.table_name)
                self.entry.append(keys)
            else:
                print("Entry already exist in %s, won't insert twice!"%self.table_name)
                self.log.info("Added entry failed :%s Entry already exist, won't insert twice!"%self.table_name)
    def config_mirror(self,sid,port):

        # self.mirror_cfg_table.entry_del(
        #         self.target,
        #         [self.mirror_cfg_table.make_key([self.gc.KeyTuple('$sid', sid)])])
        try:
            resp = self.mirror_cfg_table.entry_get(
                self.target,
                [self.mirror_cfg_table.make_key([self.gc.KeyTuple('$sid', sid)])],
                {"from_hw": True},
                self.mirror_cfg_table.make_data([self.gc.DataTuple('$direction'),
                                            self.gc.DataTuple('$ucast_egress_port'),
                                            self.gc.DataTuple('$ucast_egress_port_valid'),
                                            self.gc.DataTuple('$session_enable')],
                                            '$normal')
            )
            data_dict = next(resp)[0].to_dict()
        except:
            self.mirror_cfg_table.entry_add(
                    self.target,
                    [self.mirror_cfg_table.make_key([self.gc.KeyTuple('$sid', sid)])],
                    [self.mirror_cfg_table.make_data([self.gc.DataTuple('$direction', str_val="INGRESS"),
                                                    self.gc.DataTuple('$ucast_egress_port', port),
                                                    self.gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                    self.gc.DataTuple('$session_enable', bool_val=True)],
                                                '$normal')]
                )
            self.log.info("Configure mirror success: %d"%sid)
        else:
            print("\n!!! Mirror session has been enable, won't set twice.")
            self.log.info("Configure mirror failed: Mirror session %d has been enable, won't set twice"%sid)
        resp = self.mirror_cfg_table.entry_get(self.target, None, {"from_hw": True})#read all entry in mirror_cfg_table
        resp2 = self.mirror_cfg_table.entry_get(self.target, None, {"from_hw": True})
        length = len(list(resp2))
        print("\nR---->Table: %s, %d entry"%("$mirror.cfg",length))
        for data,key in resp:
            print(key)
            print(data)
        print()

class TestDDoS(object):
    import logging

    from bfrt_grpc.client import BfruntimeRpcException
    def __init__(self):
        super(TestDDoS,self).__init__()

        self.log = logging.getLogger(__name__)
        self.log.info('Test for p4 programs')

        # CPU PCIe port
        self.cpu_port = 192
        self.port_list = [
            (2,0,10,'none',2),
            (2,1,10,'none',2), # 141 -- 10.21.0.233-eth2-10.22.0.201
            (2,2,10,'none',2), # 142 -- 10.21.0.230-eth2-10.22.0.200
            (2,3,10,'none',2)]

    def get_dev_port(self, fp_port, lane):
        ''' Convert front-panel port to dev port.
            Keyword arguments:
                fp_port -- front panel port number
                lane -- lane number
            Returns:
                (success flag, dev port or error message)
        '''
        resp = self.port_hdl_info_table.entry_get(self.target, [
            self.port_hdl_info_table.make_key([
                self.gc.KeyTuple('$CONN_ID', fp_port),
                self.gc.KeyTuple('$CHNL_ID', lane)
            ])
        ], {'from_hw': False})

        try:
            dev_port = next(resp)[0].to_dict()['$DEV_PORT']
        except BfruntimeRpcException:
            return (False, 'Port {}/{} not found!'.format(fp_port, lane))
        else:
            return (True, dev_port)

    def get_fp_port(self, dev_port):
        ''' Get front panel port from dev port.
            Returns:
                (success flag, port or error message, lane or None)
        '''

        # If we haven't filled the reverse mapping dict yet, do so
        if self.dev_port_to_fp_port is None:
            self.dev_port_to_fp_port = {}

            # Get all ports
            resp = self.port_hdl_info_table.entry_get(self.target, [],
                                                      {'from_hw': False})

            # Fill in dictionary
            for v, k in resp:
                v = v.to_dict()
                k = k.to_dict()
                self.dev_port_to_fp_port[v['$DEV_PORT']] = (
                    k['$CONN_ID']['value'], k['$CHNL_ID']['value'])

        # Look up front panel port/lane from dev port
        if dev_port in self.dev_port_to_fp_port:
            return (True,) + self.dev_port_to_fp_port[dev_port]
        else:
            return (False, 'Invalid dev port {}'.format(dev_port), None)

    def add_port(self, front_panel_port, lane, speed, fec, an):
        ''' Add one port.
            Keyword arguments:
                front_panel_port -- front panel port number
                lane -- lane within the front panel port
                speed -- port bandwidth in Gbps, one of {10, 25, 40, 50, 100}
                fec -- forward error correction, one of {'none', 'fc', 'rs'}
                autoneg -- autonegotiation, one of {'default', 'enable', 'disable'}
            Returns:
                (success flag, None or error message)
        '''

        speed_conversion_table = {
            10: 'BF_SPEED_10G',
            25: 'BF_SPEED_25G',
            40: 'BF_SPEED_40G',
            50: 'BF_SPEED_50G',
            100: 'BF_SPEED_100G'
        }

        fec_conversion_table = {
            'none': 'BF_FEC_TYP_NONE',
            'fc': 'BF_FEC_TYP_FC',
            'rs': 'BF_FEC_TYP_RS'
        }

        an_conversion_table = {
            'default': 'PM_AN_DEFAULT',
            'enable': 'PM_AN_FORCE_ENABLE',
            'disable': 'PM_AN_FORCE_DISABLE',
            0: 'PM_AN_DEFAULT',
            1: 'PM_AN_FORCE_ENABLE',
            2: 'PM_AN_FORCE_DISABLE'
        }

        success, dev_port = self.get_dev_port(front_panel_port, lane)
        if not success:
            return (False, dev_port)

        if dev_port in self.active_ports:
            msg = 'Port {}/{} already in active ports list'.format(
                front_panel_port, lane)
            self.log.warning(msg)
            return (False, msg)

        self.port_table.entry_add(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', dev_port)])
        ], [
                                      self.port_table.make_data([
                                          self.gc.DataTuple('$SPEED',
                                                            str_val=speed_conversion_table[speed]),
                                          self.gc.DataTuple('$FEC', str_val=fec_conversion_table[fec]),
                                          self.gc.DataTuple('$AUTO_NEGOTIATION',
                                                            str_val=an_conversion_table[an]),
                                          self.gc.DataTuple('$PORT_ENABLE', bool_val=True)
                                      ])
                                  ])
        self.log.info('Added port: {}/{} {}G {} {}'.format(
            front_panel_port, lane, speed, fec, an))

        self.active_ports.append(dev_port)

        return (True, None)

    def add_ports(self, port_list):
        ''' Add ports.
            Keyword arguments:
                port_list -- a list of tuples: (front panel port, lane, speed, FEC string, autoneg) where:
                 front_panel_port is the front panel port number
                 lane is the lane within the front panel port
                 speed is the port bandwidth in Gbps, one of {10, 25, 40, 50, 100}
                 fec (forward error correction) is one of {'none', 'fc', 'rs'}
                 autoneg (autonegotiation) is one of {'default', 'enable', 'disable'}
            Returns:
                (success flag, None or error message)
        '''

        for (front_panel_port, lane, speed, fec, an) in port_list:
            success, error_msg = self.add_port(front_panel_port, lane, speed,
                                               fec, an)
            if not success:
                return (False, error_msg)

        return (True, None)

    def remove_port(self, front_panel_port, lane):
        ''' Remove one port.
            Keyword arguments:
                front_panel_port -- front panel port number
                lane -- lane within the front panel port
            Returns:
                (success flag, None or error message)
        '''

        success, dev_port = self.get_dev_port(front_panel_port, lane)
        if not success:
            return (False, dev_port)

        # Remove on switch
        self.port_table.entry_del(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', dev_port)])
        ])

        self.log.info('Removed port: {}/{}'.format(front_panel_port, lane))

        # Remove from our local active port list
        self.active_ports.remove(dev_port)

        return (True, None)

    def get_stats(self, front_panel_port=None, lane=None):
        ''' Get active ports statistics.
            If a port/lane is provided, it will return only stats of that port.
            Keyword arguments:
                front_panel_port -- front panel port number
                lane -- lane within the front panel port
            Returns:
                (success flag, stats or error message)
        '''

        if front_panel_port:
            if not lane:
                lane = 0

            success, dev_port = self.get_dev_port(front_panel_port, lane)
            if not success:
                return (False, dev_port)

            dev_ports = [dev_port]

            if dev_port not in self.active_ports:
                return (False,
                        'Port {}/{} not active'.format(front_panel_port, lane))
        else:
            if self.active_ports:
                dev_ports = self.active_ports
            else:
                return (False, 'No active ports')

        # Get stats
        stats_result = self.port_stats_table.entry_get(self.target, [
            self.port_stats_table.make_key([self.gc.KeyTuple('$DEV_PORT', i)])
            for i in dev_ports
        ], {'from_hw': True})

        # Construct stats dict indexed by dev_port
        stats = {}
        for v, k in stats_result:
            v = v.to_dict()
            k = k.to_dict()
            dev_port = k['$DEV_PORT']['value']
            stats[dev_port] = v

        # Get port info
        ports_info = self.port_table.entry_get(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', i)])
            for i in dev_ports
        ], {'from_hw': False})

        # Combine ports info and statistics
        values = []
        for v, k in ports_info:
            v = v.to_dict()
            k = k.to_dict()

            # Insert dev_port into result dict
            dev_port = k['$DEV_PORT']['value']
            v['$DEV_PORT'] = dev_port

            # Remove prefixes from FEC and SPEED
            v['$FEC'] = v['$FEC'][len('BF_FEC_TYP_'):]
            v['$SPEED'] = v['$SPEED'][len('BF_SPEED_'):]

            # Add port stats
            v['bytes_received'] = stats[dev_port]['$OctetsReceivedinGoodFrames']
            v['packets_received'] = stats[dev_port]['$FramesReceivedOK']
            v['errors_received'] = stats[dev_port]['$FrameswithanyError']
            v['FCS_errors_received'] = stats[dev_port][
                '$FramesReceivedwithFCSError']
            v['bytes_sent'] = stats[dev_port]['$OctetsTransmittedwithouterror']
            v['packets_sent'] = stats[dev_port]['$FramesTransmittedOK']
            v['errors_sent'] = stats[dev_port]['$FramesTransmittedwithError']

            # Add to combined list
            values.append(v)

        # Sort by front panel port/lane
        values.sort(key=lambda x: (x['$CONN_ID'], x['$CHNL_ID']))

        return (True, values)

    def reset_stats(self):
        ''' Reset statistics of all ports '''

        self.port_stats_table.entry_mod(self.target, [
            self.port_stats_table.make_key([self.gc.KeyTuple('$DEV_PORT', i)])
            for i in self.active_ports
        ], [
                                            self.port_stats_table.make_data([
                                                self.gc.DataTuple('$FramesReceivedOK', 0),
                                                self.gc.DataTuple('$FramesReceivedAll', 0),
                                                self.gc.DataTuple('$OctetsReceivedinGoodFrames', 0),
                                                self.gc.DataTuple('$FrameswithanyError', 0),
                                                self.gc.DataTuple('$FramesReceivedwithFCSError', 0),
                                                self.gc.DataTuple('$FramesTransmittedOK', 0),
                                                self.gc.DataTuple('$FramesTransmittedAll', 0),
                                                self.gc.DataTuple('$OctetsTransmittedwithouterror', 0),
                                                self.gc.DataTuple('$FramesTransmittedwithError', 0)
                                            ])
                                        ] * len(self.active_ports))

    def set_loopback_mode(self, ports):
        ''' Sets loopback mode in front panel ports.
            Keyword arguments:
                ports -- list of dev port numbers
        '''

        self.port_table.entry_add(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', dev_port)])
            for dev_port in ports
        ], [
                                      self.port_table.make_data([
                                          self.gc.DataTuple('$SPEED', str_val='BF_SPEED_100G'),
                                          self.gc.DataTuple('$FEC', str_val='BF_FEC_TYP_NONE'),
                                          self.gc.DataTuple('$LOOPBACK_MODE', str_val='BF_LPBK_MAC_NEAR'),
                                          self.gc.DataTuple('$PORT_ENABLE', bool_val=True)
                                      ])
                                  ] * len(ports))

        self.loopback_ports.extend(ports)

        self.log.info('{} front panel ports set in loopback mode'.format(
            len(ports)))

    def remove_loopback_ports(self):
        ''' Remove front panel ports previously set in loopback mode '''

        self.port_table.entry_del(self.target, [
            self.port_table.make_key([self.gc.KeyTuple('$DEV_PORT', dev_port)])
            for dev_port in self.loopback_ports
        ])

        self.log.info('Removed {} front panel ports in loopback mode'.format(
            len(self.loopback_ports)))

        self.loopback_ports = []

    def set_loopback_mode_pktgen(self, ports=[192, 448]):
        ''' Sets pktgen ports in loopback mode.
            Keyword arguments:
                ports -- list of pktgen dev port numbers (default [192,448])
            Returns True on success, False otherwise.
        '''

        try:
            self.pktgen_port_cfg_table.entry_add(self.target, [
                self.pktgen_port_cfg_table.make_key(
                    [self.gc.KeyTuple('dev_port', port)]) for port in ports
            ], [
                                                     self.pktgen_port_cfg_table.make_data(
                                                         [self.gc.DataTuple('recirculation_enable', bool_val=True)])
                                                 ] * len(ports))
        except Exception as e:
            self.log.exception(e)
            return False
        else:
            self.log.info('PktGen ports {} set in loopback mode'.format(ports))

    def get_loopback_mode_pktgen(self, ports=[192, 448]):
        ''' Gets loopback mode status of pktgen ports.
            Keyword arguments:
                ports -- list of pktgen dev port numbers (default [192,448])
            Returns True if all ports are in loopback mode, False otherwise.
        '''

        # Check ports state
        resp = self.pktgen_port_cfg_table.entry_get(self.target, [
            self.pktgen_port_cfg_table.make_key(
                [self.gc.KeyTuple('dev_port', port)]) for port in ports
        ], {'from_hw': False})

        loopback_mode = True
        for v, k in resp:
            v = v.to_dict()
            k = k.to_dict()

            if not v['recirculation_enable']:
                loopback_mode = False
                break
        return loopback_mode

    def critical_error(self, msg):
        self.log.critical(msg)
        print(msg, file=sys.stderr)
        logging.shutdown()
        #sys.exit(1)
        os.kill(os.getpid(), signal.SIGTERM)

    def setup(self, p4_name, bfrt_ip, bfrt_port):
        self.dev = 0
        self.target = gc.Target(self.dev, pipe_id=0xFFFF)

        # Connect to BFRT server
        try:
            interface = gc.ClientInterface('{}:{}'.format(bfrt_ip, bfrt_port),
                                           client_id=0,
                                           device_id=self.dev)
        except RuntimeError as re:
            msg = re.args[0] % re.args[1]
            self.critical_error(msg)
        else:
            self.log.info('Connected to BFRT server {}:{}'.format(
                bfrt_ip, bfrt_port))

        try:
            interface.bind_pipeline_config(p4_name)
        except gc.BfruntimeForwardingRpcException:
            self.critical_error('P4 program {} not found!'.format(p4_name))

        try:
            self.bfrt_info = interface.bfrt_info_get(p4_name)
            self.log = logging.getLogger(__name__)
            self.gc = gc

            # Get port table
            self.port_table = self.bfrt_info.table_get('$PORT')

            # Statistics table
            self.port_stats_table = self.bfrt_info.table_get('$PORT_STAT')

            # Front-panel port to dev port lookup table
            self.port_hdl_info_table = self.bfrt_info.table_get('$PORT_HDL_INFO')

            # dev port to FP port reverse lookup table (lazy initialization)
            self.dev_port_to_fp_port = None

            # List of active ports
            self.active_ports = []

            # List of ports in loopback mode
            self.loopback_ports = []

            # PktGen table to configure pktgen ports in loopback mode
            self.pktgen_port_cfg_table = self.bfrt_info.table_get('$PKTGEN_PORT_CFG')
            # Get all tables for program

            # Port configuration
            self.add_ports(self.port_list)

        except KeyboardInterrupt:
            self.critical_error('Stopping controller.')
        except Exception as e:
            self.log.exception(e)
            self.critical_error('Unexpected error. Stopping controller.')

    def runTest(self):
        # Set default output port
        # Parse the payload and extract the timestamps
        # import pdb; pdb.set_trace()
        # # add entry--exact
        # table1 = Table(self.target, gc, self.bfrt_info, "flood_detection")
        # table1.clearEntry()
        # key1 = [("hdr.ipv4.protocol",17),("hdr.ipv4.dst_addr","10.22.0.201"),("hdr.udp.src_port",80)]
        # table1.addEntry("exact",key1,"apply_hash1",[])
        # table1.readTable_tbl()

        # add entry--ternary
        table1 = Table(self.target, gc, self.bfrt_info, "src_entropy","SwitchIngress")
        table2 = Table(self.target, gc, self.bfrt_info, "dst_entropy","SwitchIngress")
        table3 = Table(self.target, gc, self.bfrt_info, "src2_entropy","SwitchIngress")
        table4 = Table(self.target, gc, self.bfrt_info, "dst2_entropy","SwitchIngress")
        table5 = Table(self.target, gc, self.bfrt_info, "dst_flag","SwitchEgress")
        table6 = Table(self.target, gc, self.bfrt_info, "dst_key","SwitchEgress")

        table1.clearEntry()
        table2.clearEntry()
        table3.clearEntry()
        table4.clearEntry()
        table5.clearEntry()
        table6.clearEntry()
        table1.addEntry("exact", [("ig_md.md_ddos.src_cnt3", 1)], "src_entropy_compute", [("entropy_term",0)])
        table2.addEntry("exact", [("ig_md.md_ddos.dst_cnt3", 1)], "dst_entropy_compute", [("entropy_term",0)])
        table3.addEntry("exact", [("ig_md.md_ddos.src_cnt13", 1)], "src_entropy_compute", [("entropy_term",0)])
        table4.addEntry("exact", [("ig_md.md_ddos.dst_cnt13", 1)], "dst_entropy_compute", [("entropy_term",0)])
        #table1.addEntry("exact", [1], "dst_entropy_compute", [0])
        for i in range(2,8191):
            result =  i*math.log2(i)-(i-1)*math.log2(i-1)
            table1.addEntry("exact", [("ig_md.md_ddos.src_cnt3", i)], "src_entropy_compute", [("entropy_term",round(result))])
            table2.addEntry("exact", [("ig_md.md_ddos.dst_cnt3", i)], "dst_entropy_compute", [("entropy_term",round(result))])
            table3.addEntry("exact", [("ig_md.md_ddos.src_cnt13", i)], "src_entropy_compute", [("entropy_term",round(result))])
            table4.addEntry("exact", [("ig_md.md_ddos.dst_cnt13", i)], "dst_entropy_compute", [("entropy_term",round(result))])
         #   table1.addEntry("exact", [i], "dst_entropy_compute", [result])
        for i in range(1000):
            flag=0
            for j in range(1,256):
                key = table6.readRegister(j)
                if key !=0:
                    print(hex_to_ip(key), end = '\t')
                    flag=1
            if flag is 0:
                print("safe\n")

            time.sleep(1)

if __name__ =='__main__':

#-----------------------------------------------------------------------------------------------------
    # Parse arguments
    argparser = argparse.ArgumentParser(description='controller.')
    argparser.add_argument('--p4_name',
                           type=str,
                           default='ddos_detection',
                           help='P4 program name. Default: ddos_detection')
    argparser.add_argument(
        '--bfrt-ip',
        type=str,
        default='127.0.0.1',
        help='Name/address of the BFRuntime server. Default: 127.0.0.1')
    argparser.add_argument('--bfrt-port',
                           type=int,
                           default=50052,
                           help='Port of the BFRuntime server. Default: 50052')
    argparser.add_argument('--log-level',
                           default='INFO',
                           choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'],
                           help='Default: INFO')
    args = argparser.parse_args()

    # Configure logging
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        sys.exit('Invalid log level: {}'.format(args.log_level))

    logformat = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='ddos_detection.log',
                        filemode='w',
                        level=numeric_level,
                        format=logformat,
                        datefmt='%H:%M:%S')
#---------------------------------------------------------------------------------------------

    args.bfrt_ip = args.bfrt_ip.strip()
    args.p4_name = "ddos_detection"

    ctrl = TestDDoS()
    ctrl.setup(args.p4_name, args.bfrt_ip, args.bfrt_port)
    ctrl.runTest()