using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PackageCollections
{
	#region 协议
	public struct ip_v4_address
	{
		public byte byte1;
		public byte byte2;
		public byte byte3;
		public byte byte4;
	};
	public struct ip_v6_address
	{
		public ushort part1;
		public ushort part2;
		public ushort part3;
		public ushort part4;
		public ushort part5;
		public ushort part6;
		public ushort part7;
		public ushort part8;
	};
	public struct mac_address
	{
		public byte byte1;
		public byte byte2;
		public byte byte3;
		public byte byte4;
		public byte byte5;
		public byte byte6;
	};
	public struct ethernet_header
	{
		public mac_address des_mac_addr;
		public mac_address src_mac_addr;
		public ushort type;
	};
	public struct ip_v4_header
	{
		public byte ver_ihl;     // Version (4 bits) + Internet header length (4 bits)
		public byte tos;         // Type of service 
		public ushort tlen;           // Total length 
		public ushort identification; // Identification
		public ushort flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
		public byte ttl;         // Time to live
		public byte proto;           // Protocol
		public ushort checksum;           // Header checksum
		public ip_v4_address src_ip_addr;      // Source address
		public ip_v4_address des_ip_addr;      // Destination address
		public uint op_pad;           // Option + Padding
	};
	public struct ip_v6_header
	{
		public uint ver_trafficclass_flowlabel;
		public ushort payload_len;
		public byte next_head;
		public byte ttl;
		public ip_v6_address src_ip_addr;
		public ip_v6_address dst_ip_addr;
	};
	public struct arp_header
	{
		public ushort hardware_type;
		public ushort protocol_type;
		public byte hardware_length;
		public byte protocol_length;
		public ushort operation_code;
		public mac_address source_mac_addr;
		public ip_v4_address source_ip_addr;
		public mac_address des_mac_addr;
		public ip_v4_address des_ip_addr;
	};
	public struct tcp_header
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
	};
	public struct udp_header
	{
		public ushort sport;          // Source port
		public ushort dport;          // Destination port
		public ushort len;            // Datagram length
		public ushort checksum;           // Checksum
	};
	public struct icmp_header
	{
		public byte type;
		public byte code;
		public ushort checksum;
		public ushort id;
		public ushort sequence;
	};
	#endregion
	public struct pcap_pkthdr
	{
		public timeval ts; /* time stamp */
		public uint caplen; /* length of portion present */
		public uint len;    /* length this packet (off wire) */
	};
	public struct timeval
	{
		public uint tv_sec;         /* seconds */
		public uint tv_usec;        /* and microseconds */
	};
	public struct PackageHandle
	{
		public pcap_pkthdr header;
		public byte[] pkt_data;
	}
}
