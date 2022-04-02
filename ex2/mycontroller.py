#!/usr/bin/env python3
# 引入了需要用到的库和p4runtime_lib
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

SWITCH_TO_HOST_PORT = 1

# 定义写隧道规则
def writeTunnelRules(p4info_helper, ingress_sw, egress_sw, tunnel_id,
                     dst_eth_addr, dst_ip_addr, switch_port):
    """
    安装三个规则:
    1) Tunnel Ingress Rule(交换机入口ipv4_lpm表中隧道入口规则)：用特定的ID将流封装到隧道中;
    2) Tunnel Transit Rule(交换机入口的转发规则)：基于特定ID的转发，实现所有主机互通;
    3) Tunnel Egress Rule(交换机出口的隧道出口规则)：用特定ID将流解封装,并转发到相应主机。

    :param p4info_helper: the P4Info helper
    :param ingress_sw: the ingress switch connection
    :param egress_sw: the egress switch connection
    :param tunnel_id: 指定的隧道ID
    :param dst_eth_addr: the destination IP to match in the ingress rule
    :param dst_ip_addr: 要写入的目标以太网地址
    """
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(    # 使用p4info_helper解析器将规则转化为P4Runtime能够识别的形式
        table_name="MyIngress.ipv4_lpm",            # 定义表名
        match_fields={                              # 设置匹配域
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)   # 包头对应的hdr.ipv4.dstAddr字段与参数中的dst_ip_addr匹配，则执行这一条表项的对应动作
                                                    # 后面的32是掩码，表示前32bit都是网络号
        },
        action_name="MyIngress.myTunnel_ingress",   # 设置匹配成功对应的动作名
        action_params={                             # 动作参数
            "dst_id": tunnel_id,                    # 为传入的tunnel_id
        })
    ingress_sw.WriteTableEntry(table_entry)         # 调用WriteTableEntry，将生成的匹配动作表项加入交换机
    print("Installed ingress tunnel rule on %s" % ingress_sw.name)

    # 2) Tunnel Transit Rule
    # 将规则添加到myTunnel_exact表中并匹配隧道ID（hdr.myTunnel.dst_id）。
    # 转发流量在连接到下一个交换机的端口上使用myTunnel_forward操作。
    # s1和s2使用连接到两个交换机上的端口2的链接。
    # 在文件的开头定义了，SWITCH_TO_SWITCH_PORT，可以用作输出此操作的端口。
    # 我们只需要入换机上的传输规则，因为我们是使用简单拓扑。
    # 通常，需要使用传输规则路径中的每个交换机（最后一个交换机除外，它有出口规则），为每个交换机动态选择端口基于拓扑。

    # ①TODO build the transit rule
    # TODO install the transit rule on the ingress switch
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",     # 定义表名
        match_fields={                             # 设置匹配域
            "hdr.myTunnel.dst_id": tunnel_id       # 匹配隧道ID（hdr.myTunnel.dst_id）
        },
        action_name="MyIngress.myTunnel_forward",  # 设置匹配成功对应的动作名
        action_params={                            # 动作参数
            "port": switch_port                    # 端口选择switch_port

        })
    ingress_sw.WriteTableEntry(table_entry)        # 调用WriteTableEntry，将生成的匹配动作表项加入交换机
    print("Installed transit tunnel rule on %s" % ingress_sw.name)

    # 3) Tunnel Egress Rule
    # For our simple topology, the host will always be located on the
    # SWITCH_TO_HOST_PORT (port 1).
    # In general, you will need to keep track of which port the host is
    # connected to.
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",     # 定义表名
        match_fields={                             # 设置匹配域
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_egress",   # 设置匹配成功对应的动作名
        action_params={                            # 动作参数
            "dstAddr": dst_eth_addr,
            "port": SWITCH_TO_HOST_PORT
        })
    egress_sw.WriteTableEntry(table_entry)
    print("Installed egress tunnel rule on %s" % egress_sw.name)


# 将交换机中所有流表所有条目全部读出来，打印出来。
def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # ②TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()


# 从交换机中读具体的索引（即隧道ID号）对应的计数器
def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")
        
        # Write the rules that tunnel traffic from h1 to h2
        writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=100,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2", switch_port=2)

        # Write the rules that tunnel traffic from h2 to h1
        writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=101,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1", switch_port=2)

        # Write the rules that tunnel traffic from h1 to h3
        writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s3, tunnel_id=200,
                         dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3", switch_port=3)

        # Write the rules that tunnel traffic from h3 to h1
        writeTunnelRules(p4info_helper, ingress_sw=s3, egress_sw=s1, tunnel_id=201,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1", switch_port=2)

        # Write the rules that tunnel traffic from h2 to h3
        writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s3, tunnel_id=300,
                         dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3", switch_port=3)

        # Write the rules that tunnel traffic from h3 to h2
        writeTunnelRules(p4info_helper, ingress_sw=s3, egress_sw=s2, tunnel_id=301,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2", switch_port=3)

        # ③TODO Uncomment the following two lines to read table entries from s1 and s2
        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)

        # Print the tunnel counters every 2 seconds
        while True:
            sleep(2)
            print('\n----- Reading tunnel counters -----')
            print('\n----- s1 ->  s2 -----')
            printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 100)
            printCounter(p4info_helper, s2, "MyIngress.egressTunnelCounter", 100)
            print('\n----- s2 ->  s1 -----')
            printCounter(p4info_helper, s2, "MyIngress.ingressTunnelCounter", 101)
            printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 101)
            print('\n----- s1 ->  s3 -----')
            printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 200)
            printCounter(p4info_helper, s3, "MyIngress.egressTunnelCounter", 200)
            print('\n----- s3 ->  s1 -----')
            printCounter(p4info_helper, s3, "MyIngress.ingressTunnelCounter", 201)
            printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 201)
            print('\n----- s2 ->  s3 -----')
            printCounter(p4info_helper, s2, "MyIngress.ingressTunnelCounter", 300)
            printCounter(p4info_helper, s3, "MyIngress.egressTunnelCounter", 300)
            print('\n----- s3 ->  s2 -----')
            printCounter(p4info_helper, s3, "MyIngress.ingressTunnelCounter", 301)
            printCounter(p4info_helper, s2, "MyIngress.egressTunnelCounter", 301)
            print('\n----- Finished -----')

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
