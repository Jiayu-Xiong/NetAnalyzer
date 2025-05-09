using System;
using System.Collections.Generic;
using System.Text;

namespace PackageCollections
{
    public struct Ethernet_Header
    {
        public ushort type;
        public byte[] dst_mac;
        public byte[] src_mac;
    }
    public struct Arp_Header
    {
        public ushort hardware_type;
        public ushort protocol_type;
        public byte hardware_length;
        public byte protocol_length;
        public ushort operation_code;
        public byte[] dst_mac;
        public byte[] dst_ipv4;
        public byte[] src_mac;
        public byte[] src_ipv4;
    }
    public struct IP_V4_Header
    {
        public byte version;
        public byte hlen;
        public byte tos;
        public ushort tlen;
        public ushort identification;
        public ushort flag;
        public ushort offset;
        public byte ttl;
        public byte proto;
        public ushort checksum;
        public byte[] dst_ipv4;
        public byte[] src_ipv4;
        public uint op_pad;
    }
    public struct IP_V6_Header
    {
        public int version;
        public int traffic_class;
        public int flow_label;
        public ushort payload_len;
        public byte next_head;
        public byte ttl;
        public ushort[] dst_ipv6;
        public ushort[] src_ipv6;
    }
    public struct Udp_Header
    {
        public ushort sport;
        public ushort dport;
        public ushort len;
        public ushort checksum;
    }
    public struct Tcp_Header
    {
        public ushort sport;
        public ushort dport;
        public uint sequence;
        public uint acknowledgement;
        public byte offset;
        public byte flags;
        public ushort windows;
        public ushort checksum;
        public ushort urgent_pointer;
    }
    public struct Icmp_Header
    {
        public byte type;
        public byte code;
        public ushort checksum;
        public ushort id;
        public ushort sequence;
    }
}
