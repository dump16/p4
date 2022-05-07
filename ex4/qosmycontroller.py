#!/usr/bin/env python3
# 引入了需要用到的库和p4runtime_lib
import argparse
import os
import sys
from time import sleep

import grpc

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def writeRule(p4info_helper, ingress_sw,
              dst_eth_addr, dst_ip_addr, switch_port):
    table_entry = p4info_helper.buildTableEntry(    # 使用p4info_helper解析器将规则转化为P4Runtime能够识别的形式
        table_name="MyIngress.ipv4_lpm",            # 定义表名
        match_fields={                              # 设置匹配域
            "hdr.ipv4.dstAddr": dst_ip_addr         # 包头对应的hdr.ipv4.dstAddr字段与参数中的dst_ip_addr匹配，则执行这一条表项的对应动作
        },
        action_name="MyIngress.ipv4_forward",       # 设置匹配成功对应的动作名
        action_params={                             # 动作参数
            "dstAddr": dst_eth_addr,
            "port": switch_port
        })
    ingress_sw.WriteTableEntry(table_entry)         # 调用WriteTableEntry，将生成的匹配动作表项加入交换机
    print("Installed rule on %s" % ingress_sw.name)


def main(p4info_file_path, bmv2_file_path):
    # 初始化 p4info_helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # 为s1、s2、s3创建交换机连接对象
        # 这是由一个运行时gRPC连接支持的
        # 此外，将发送给交换机的所有 P4Runtime 消息转存到给定的 txt 文件
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

        # 在交换机上安装 P4 程序
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        writeRule(p4info_helper, ingress_sw=s1,
                   dst_eth_addr="08:00:00:00:01:01", dst_ip_addr=("10.0.1.1", 32), switch_port=2)
        writeRule(p4info_helper, ingress_sw=s1,
                   dst_eth_addr="08:00:00:00:01:11", dst_ip_addr=("10.0.1.11", 32), switch_port=1)
        writeRule(p4info_helper, ingress_sw=s1,
                   dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=("10.0.2.0", 24), switch_port=3)
        writeRule(p4info_helper, ingress_sw=s1,
                   dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=("10.0.3.0", 24), switch_port=4)

        writeRule(p4info_helper, ingress_sw=s2,
                   dst_eth_addr="08:00:00:00:02:02", dst_ip_addr=("10.0.2.2", 32), switch_port=2)
        writeRule(p4info_helper, ingress_sw=s2,
                   dst_eth_addr="08:00:00:00:02:22", dst_ip_addr=("10.0.2.22", 32), switch_port=1)
        writeRule(p4info_helper, ingress_sw=s2,
                   dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=("10.0.1.0", 24), switch_port=3)
        writeRule(p4info_helper, ingress_sw=s2,
                   dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=("10.0.3.0", 24), switch_port=4)

        writeRule(p4info_helper, ingress_sw=s3,
                   dst_eth_addr="08:00:00:00:03:03", dst_ip_addr=("10.0.3.3", 32), switch_port=1)
        writeRule(p4info_helper, ingress_sw=s3,
                   dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=("10.0.1.0", 24), switch_port=2)
        writeRule(p4info_helper, ingress_sw=s3,
                   dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=("10.0.2.0", 24), switch_port=3)

        while True:
            sleep(2)
        
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/qos.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/qos.json')
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
