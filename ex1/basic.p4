/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;    //帧类型
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    macAddr_t  sha;  //发送方MAC地址
    ip4Addr_t  spa;  //发送方ip地址
    macAddr_t  tha;  //目标MAC地址
    ip4Addr_t  tpa;  //目标ip地址
}

struct metadata {
    ip4Addr_t       dst_ipv4;
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,	    //out相当于输出的数据,type是headers
                inout metadata meta,	//inout同时作为输入和输出值，类似c++里面的引用
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;      //转移到parse_ethernet状态（解析以太网包头）
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);   //提取以太网包头
        transition select(hdr.ethernet.etherType) { //根据etherType的值（协议类型）选择下一个状态
            //类似switch...case
            TYPE_IPV4 : parse_ipv4;     //转换到parse_ipv4状态（解析ip包头）
            TYPE_ARP  : parse_arp;
            default   : accept;         //默认是接受，进入下一步处理
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }  

    state parse_ipv4 {
        packet.extract(hdr.ipv4);       //提取ip包头
        transition accept;              //接受，进入下一步处理
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);  //内置函数，将当前数据包标记为即将丢弃的数据包
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {//②
        //转发需要以下几个步骤
        standard_metadata.egress_spec = port;          //设置下一跃点的出口端口
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;   //使用交换机的地址更新以太网源地址
        hdr.ethernet.dstAddr = dstAddr;                //使用下一跃点的地址更新以太网目标地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;               //递减生存时间TTL
    }


    table ipv4_lpm {
        key = {                        //匹配域
            hdr.ipv4.dstAddr: lpm;     //匹配字段是数据包头部字段中的ipv4头部的目标地址
                                       //lpm是最长前缀匹配 
        }
        actions = {                    //动作类型集合
            ipv4_forward;              //自定义的转发动作
            drop;                      //丢弃动作
            NoAction;                  //空动作
        }
        size = 1024;                   //流表可以容纳多少流表项
        default_action = drop();       //默认是丢弃
    }

    action send_arp_reply(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = dstAddr;
        
        hdr.arp.oper         = ARP_OPER_REPLY;
        
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = dstAddr;
        hdr.arp_ipv4.spa     = meta.dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    
    table arp_exact {
        key = {
            hdr.arp.oper    : exact;
            hdr.arp_ipv4.tpa: lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        //当ipv4头部有效，应用ipv4_lpm表
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        //当arp头部有效，应用arp_exact表
        else if (hdr.arp.isValid()) {
            arp_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);     //按顺序，发射
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
