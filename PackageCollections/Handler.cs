using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Windows;

namespace PackageCollections
{
    public class Handler:Analyzer
    {
		public Handler(Package package, int index) : base(package, index) { }
		public Handler(Package package) : base(package) { }
		private ushort ntohs(ushort arg)
        {
			return (ushort)IPAddress.NetworkToHostOrder((short)arg);
		}
		private uint ntohl(uint arg)
		{
			return (uint)IPAddress.NetworkToHostOrder((int)arg);
		}
		private ushort[] IPV6_Address_Convert(ip_v6_address ip_addr)
		{
			ushort[] ipv6 = new ushort[8];
			ipv6[0] = ip_addr.part1;
			ipv6[1] = ip_addr.part2;
			ipv6[2] = ip_addr.part3;
			ipv6[3] = ip_addr.part4;
			ipv6[4] = ip_addr.part5;
			ipv6[5] = ip_addr.part6;
			ipv6[6] = ip_addr.part7;
			ipv6[7] = ip_addr.part8;
			return ipv6;
		}
		private byte[] IPV4_Address_Convert(ip_v4_address ip_addr)
		{
			byte[] ipv4 = new byte[4];
			ipv4[0] = ip_addr.byte1;
			ipv4[1] = ip_addr.byte2;
			ipv4[2] = ip_addr.byte3;
			ipv4[3] = ip_addr.byte4;
			return ipv4;
		}
		private byte[] MAC_Address_Convert(mac_address ip_addr)
		{
			byte[] mac = new byte[6];
			mac[0] = ip_addr.byte1;
			mac[1] = ip_addr.byte2;
			mac[2] = ip_addr.byte3;
			mac[3] = ip_addr.byte4;
			mac[4] = ip_addr.byte5;
			mac[5] = ip_addr.byte6;
			return mac;
		}
        #region IP头处理程序
        public Ethernet_Header Ethernet_Package_Handler()
		{
			return Convert(Ethernet_Package_Getter());
		}
		private Ethernet_Header Convert(ethernet_header args)
        {
			Ethernet_Header eh = new Ethernet_Header();
			eh.dst_mac = MAC_Address_Convert(args.des_mac_addr);
			eh.src_mac = MAC_Address_Convert(args.src_mac_addr);
			eh.type = args.type;
			return eh;
		}
		public Arp_Header Arp_Package_Handler()
		{
			return Convert(Arp_Package_Getter());
		}
		private Arp_Header Convert(arp_header args)
        {
			Arp_Header ah = new Arp_Header();
			ah.operation_code = ntohs(args.operation_code);
			ah.hardware_type = ntohs(args.hardware_type);
			ah.protocol_type = ntohs(args.protocol_type);
			ah.hardware_length = args.hardware_length;
			ah.protocol_length = args.protocol_length;
			ah.dst_ipv4 = IPV4_Address_Convert(args.des_ip_addr);
			ah.src_ipv4 = IPV4_Address_Convert(args.source_ip_addr);
			ah.dst_mac = MAC_Address_Convert(args.des_mac_addr);
			ah.src_mac = MAC_Address_Convert(args.source_mac_addr);
			return ah;
		}
		public IP_V4_Header Ip_V4_Package_Handler()
		{
			return Convert(Ip_V4_Package_Getter());
		}
		private IP_V4_Header Convert(ip_v4_header args)
		{
			IP_V4_Header iH = new IP_V4_Header();
			iH.version = (byte)((args.ver_ihl & 0xf0) >> 4);
			iH.hlen = (byte)(args.ver_ihl & 0xf);
			iH.tos = args.tos;
			iH.tlen = ntohs(args.tlen);
			iH.identification = ntohs(args.identification);
			iH.flag = (ushort)((args.flags_fo & 0xE000) >> 12);
			iH.offset = (ushort)(args.flags_fo & 0x1FFF);
			iH.ttl = args.ttl;
			iH.proto = args.proto;
			iH.checksum = ntohs(args.checksum);
			iH.dst_ipv4 = IPV4_Address_Convert(args.des_ip_addr);
			iH.src_ipv4 = IPV4_Address_Convert(args.src_ip_addr);
			iH.op_pad = args.op_pad;
			return iH;
		}
		public IP_V6_Header Ip_V6_Package_Handler()
		{
			return Convert(Ip_V6_Package_Getter());
		}
		private IP_V6_Header Convert(ip_v6_header args)
        {
			IP_V6_Header iH = new IP_V6_Header();
			iH.version = (int)(args.ver_trafficclass_flowlabel & 0xf0000000) >> 28;
			iH.traffic_class = IPAddress.NetworkToHostOrder((int)(args.ver_trafficclass_flowlabel & 0x0ff00000) >> 20);
			iH.flow_label = (int)args.ver_trafficclass_flowlabel & 0x000fffff;
			iH.payload_len = args.payload_len;
			iH.next_head = args.next_head;
			iH.ttl = args.ttl;
			iH.src_ipv6 = IPV6_Address_Convert(args.src_ip_addr);
			iH.dst_ipv6 = IPV6_Address_Convert(args.dst_ip_addr);
			return iH;
		}
        #endregion
		public Tcp_Header Tcp_Package_Handler()
        {
			return Convert(Tcp_Package_Getter());
        }
		private Tcp_Header Convert(tcp_header args)
		{
			Tcp_Header th = new Tcp_Header();
			th.sport = ntohs(args.sport);
			th.dport = ntohs(args.dport);
			th.sequence = ntohl(args.sequence);
			th.acknowledgement = ntohl(args.acknowledgement);
			th.offset = (byte)((args.offset & 0xf0) >> 4);
			th.flags = args.flags;
			th.windows = ntohs(args.windows);
			th.checksum = ntohs(args.checksum);
			th.urgent_pointer = ntohs(args.urgent_pointer);
			return th;
		}
		public Icmp_Header Icmp_Package_Handler()
        {
			return Convert(Icmp_Package_Getter());
        }
		private Icmp_Header Convert(icmp_header args)
        {
			Icmp_Header ih = new Icmp_Header();
			ih.type = args.type;
			ih.code = args.code;
			ih.checksum = ntohs(args.checksum);
			ih.id = args.id;
			ih.sequence = args.sequence;
			return ih;
        }
		public Udp_Header Udp_Package_Handler()
        {
			return Convert(Udp_Package_Getter());
        }
		private Udp_Header Convert(udp_header args)
        {
			Udp_Header uh = new Udp_Header();
			uh.sport = ntohs(args.sport);
			uh.dport = ntohs(args.dport);
			uh.len = ntohs(args.len);
			uh.checksum = ntohs(args.checksum);
			return uh;
        }
    }
}
