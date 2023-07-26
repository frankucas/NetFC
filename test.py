################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.	Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################

import logging
import ipaddress
import random
import pdb
import cPickle as pkl

from ptf import config
from collections import namedtuple
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import grpc
import os
from pal_rpc.ttypes import *

import importlib
import unittest
import sys
import ptf
from ptf.base_tests import BaseTest
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

# tuple for future refs
key_random_tuple = namedtuple('key_random', 'dst_ip mask priority')
key_random_tuple.__new__.__defaults__ = (None, None, None)

num_pipes = int(testutils.test_param_get('num_pipes'))


def port_to_pipe(port):
    local_port = port & 0x7F
    assert (local_port < 72)
    pipe = (port >> 7) & 0x3
    assert (port == ((pipe << 7) | local_port))
    return pipe


swports = []
for device, port, ifname in config["interfaces"]:
    if port_to_pipe(port) < num_pipes:
        swports.append(port)
swports.sort()

swports_0 = []
swports_1 = []
swports_2 = []
swports_3 = []

# the following method categorizes the ports in ports.json file as belonging to either of the pipes (0, 1, 2, 3)
for port in swports:
    pipe = port_to_pipe(port)
    if pipe == 0:
        swports_0.append(port)
    elif pipe == 1:
        swports_1.append(port)
    elif pipe == 2:
        swports_2.append(port)
    elif pipe == 3:
        swports_3.append(port)

class TernaryMatchTest(BfRuntimeTest):
    def set_up_pal_module(self):
        try:
            self.pal_client_module = importlib.import_module(".".join(["pal_rpc", "pal"]))
        except:
            self.pal_client_module = None
        thrift_server = 'localhost'
        if testutils.test_param_get('thrift_server') != "":
            thrift_server = testutils.test_param_get('thrift_server')
        self.transport = TSocket.TSocket(thrift_server, 9090)

        self.transport = TTransport.TBufferedTransport(self.transport)
        bprotocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        if self.pal_client_module:
            self.pal_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "pal")
            self.pal = self.pal_client_module.Client(self.pal_protocol)
        else:
            self.pal_protocol = None
            self.pal = None
        self.transport.open()

    def get_table(self):
        self.tables = {
            "SwitchIngress.get_info_table"    : self.bfrt_info.table_get("SwitchIngress.get_info_table"),            
            "SwitchIngress.get_flag_table"    : self.bfrt_info.table_get("SwitchIngress.get_flag_table"),       
            "SwitchIngress.get_log_i_table"   : self.bfrt_info.table_get("SwitchIngress.get_log_i_table"),    
            "SwitchIngress.get_log_j_table"   : self.bfrt_info.table_get("SwitchIngress.get_log_j_table"),   
            "SwitchIngress.get_log_m_0_table" : self.bfrt_info.table_get("SwitchIngress.get_log_m_0_table"),              
            "SwitchIngress.get_log_m_1_table" : self.bfrt_info.table_get("SwitchIngress.get_log_m_1_table"),        
            "SwitchIngress.get_log_m_2_table" : self.bfrt_info.table_get("SwitchIngress.get_log_m_2_table"),    
            "SwitchIngress.get_abs_z_table"   : self.bfrt_info.table_get("SwitchIngress.get_abs_z_table"),   
        }

    def setUp(self):
        client_id = 0
        p4_name = "approximate_calculation"
        BfRuntimeTest.setUp(self, client_id, p4_name)
        self.bfrt_info = self.interface.bfrt_info_get("approximate_calculation")
        self.get_table()
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.table_path = "/root/bf-sde-9.1.0/pkgsrc/p4-examples/p4_16_programs/approximate_calculation/table"
        self.set_up_pal_module()
        self.devPorts = [128, 129, 130, 131]
        self.up_ports() 
        self.get_table_configuration()            

    def get_key_tuple_list(self, make_key_func, key_name, key_list):
        key_tuple_list = []
        length = len(key_name)
        for key in key_list:
            key_tuple_list.append(make_key_func([gc.KeyTuple(key_name[i], key[i]) for i in range(length)]))
        return key_tuple_list

    def get_data_tuple_list(self, make_data_func, data_name, data_list, action_name):
        data_tuple_list = []
        length = len(data_name)
        for data in data_list:
            data_tuple_list.append(make_data_func([gc.DataTuple(data_name[i], data[i]) for i in range(length)], action_name))
        return data_tuple_list

    def add_entry_to_get_flag_table(self):
        info_to_flag_list = [[0,0,0],[1,0,0],[2,1,0],[3,2,32768],[4,1,32768],[5,2,0],[6,0,32768],[7,0,32768]]
        for item in info_to_flag_list:
            self.get_flag_table.entry_add(
                self.target,
                [self.get_flag_table.make_key([gc.KeyTuple('ig_md.ac_md.info', item[0])])],
                [self.get_flag_table.make_data([gc.DataTuple('sign_z', item[2])],
                                        'SwitchIngress.set_flag_%d_action'%item[1])])  

    def load_table(self, table_path):
        with open(table_path,"rb") as f:
            table = pkl.load(f)        
        return table
    
    def add_entry_to_SwitchIngress_get_info_action(self):
        key_list  = [[(i&0b100)>>2, (i&0b010)>>1, (i&0b001)] for i in range(8)]
        data_list = [[i] for i in range(8)]
        return [key_list,data_list]

    def add_entry_to_SwitchIngress_get_log_action(self):
        table = self.load_table(os.path.join(self.table_path,"log_table.pkl"))
        key_list  = [[item[0]] for item in table]
        data_list = [[item[1]] for item in table]
        return [key_list,data_list]

    def add_entry_to_SwitchIngress_get_log_m_action(self, table_index=0):
        table = self.load_table(os.path.join(self.table_path,"log_mod_%d_table.pkl"%table_index))
        key_list  = [[item[0]] for item in table]
        data_list = [[item[1]] for item in table]
        return [key_list,data_list]        

    def add_entry_to_SwitchIngress_get_abs_z_action(self):
        table = self.load_table(os.path.join(self.table_path,"exp_table.pkl")) 
        key_list  = [[item[0]] for item in table]
        data_list = [[item[1]] for item in table]
        return [key_list,data_list]        

    def get_table_configuration(self):
        self.table_configuration = {
            "SwitchIngress.get_info_table" : {
                "key_name" : ['hdr.calc.x[15:15]','hdr.calc.y[15:15]','ig_md.ac_md.sign[15:15]'],
                "action_entries_dict" : {
                    "SwitchIngress.get_info_action" : [['info']]+self.add_entry_to_SwitchIngress_get_info_action()}},
            "SwitchIngress.get_flag_table" : {
                "key_name" : ['ig_md.ac_md.info'],
                "action_entries_dict" : {
                    "SwitchIngress.set_flag_0_action" : [['sign_z'], [[0],[1],[6],[7]], [[0],[0],[32768],[32768]]],
                    "SwitchIngress.set_flag_1_action" : [['sign_z'], [[2],[4]], [[0],[32768]]],
                    "SwitchIngress.set_flag_2_action" : [['sign_z'], [[3],[5]], [[32768],[0]]]}},
            "SwitchIngress.get_log_i_table" : {
                "key_name" : ['ig_md.ac_md.frac_x'],
                "action_entries_dict" : {
                    "SwitchIngress.get_log_i_action" : [['log_i']]+self.add_entry_to_SwitchIngress_get_log_action()}},
            "SwitchIngress.get_log_j_table" :  {
                "key_name" : ['ig_md.ac_md.frac_y'],
                "action_entries_dict" : {
                    "SwitchIngress.get_log_j_action" : [['log_j']]+self.add_entry_to_SwitchIngress_get_log_action()}},  
            "SwitchIngress.get_log_m_0_table" : {
                "key_name" : ['ig_md.ac_md.log_k'],
                "action_entries_dict" : {
                    "SwitchIngress.get_log_m_0_action" : [['log_m']]+self.add_entry_to_SwitchIngress_get_log_m_action(table_index=0)}},             
            "SwitchIngress.get_log_m_1_table" : {
                "key_name" : ['ig_md.ac_md.log_k'],
                "action_entries_dict" : {
                    "SwitchIngress.get_log_m_1_action" : [['log_m']]+self.add_entry_to_SwitchIngress_get_log_m_action(table_index=1)}}, 
            "SwitchIngress.get_log_m_2_table" : {
                "key_name" : ['ig_md.ac_md.log_k'],
                "action_entries_dict" : {
                    "SwitchIngress.get_log_m_2_action" : [['log_m']]+self.add_entry_to_SwitchIngress_get_log_m_action(table_index=2)}},   
            "SwitchIngress.get_abs_z_table" : {
                "key_name" : ['ig_md.ac_md.n'],
                "action_entries_dict" : {
                    "SwitchIngress.get_abs_z_action" : [['abs_z']]+self.add_entry_to_SwitchIngress_get_abs_z_action()}},   
        }

    def add_entry_to_tables(self):
        for table_name in self.table_configuration:
            for action_name in self.table_configuration[table_name]["action_entries_dict"]:
                data_name,key_list,data_list = self.table_configuration[table_name]["action_entries_dict"][action_name]
                self.tables[table_name].entry_add(self.target,
                    self.get_key_tuple_list(self.tables[table_name].make_key, self.table_configuration[table_name]["key_name"], key_list),
                    self.get_data_tuple_list(self.tables[table_name].make_data, data_name, data_list, action_name))
      
    def up_ports(self):
        for sw_port in self.devPorts:
            self.pal.pal_port_add(0, sw_port, pal_port_speed_t.BF_SPEED_10G, pal_fec_type_t.BF_FEC_TYP_NONE)
            self.pal.pal_port_an_set(0, sw_port, 2)
            self.pal.pal_port_enable(0, sw_port)

    def runTest(self):
        self.add_entry_to_tables()
        pdb.set_trace()
        
        
       


        		 
