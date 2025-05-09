using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using PackageCollections;

namespace PackageCollections
{
    public class Analyzer
    {
        protected Package package;
		protected PackageHandle _ph;
		protected int offset;
		private bool isDataComp = false;
		public byte[] data {
			get
			{
				if (isDataComp) return null;
				int Length = _ph.pkt_data.Length;
				byte[] temp = new byte[Length - offset];
				for (int circ = offset - 1; circ < Length; circ++)
				{
					temp[circ] = _ph.pkt_data[circ];
				}
				return temp;
			}
		}
		public Analyzer(Package package)
		{
			this.package = package;
		}
		public Analyzer(Package package,int index)
        {
            this.package = package;
			offset = 0;
			_ph = package.array[index];
		}
		public void ReInit(int index)
        {
			_ph = package.array[index];
			offset = 0;
			isDataComp = false;
		}
		public uint GetPackLength()
        {
			return _ph.header.len == _ph.header.caplen ? _ph.header.len : 0;
		}
        public unsafe ethernet_header Ethernet_Package_Getter()
        {
			ethernet_header eh = new ethernet_header();
			ethernet_header* tmp;
			fixed (byte* p = &_ph.pkt_data[0])
			{
				tmp = (ethernet_header*)p;
			}
			eh = *tmp;
			eh.type = (ushort)IPAddress.NetworkToHostOrder((short)tmp->type);
			return eh;
        }
		public unsafe arp_header Arp_Package_Getter()
		{
			arp_header rah = new arp_header();
			arp_header* ah;
			fixed (byte* p = &_ph.pkt_data[14])
			{
				ah = (arp_header*)p;
			}
			offset = 0;
			rah = *ah;
			return rah;
		}
		public unsafe ip_v4_header Ip_V4_Package_Getter()
		{
			ip_v4_header rih = new ip_v4_header();
			ip_v4_header* ih;
			fixed (byte* p = &_ph.pkt_data[14])
			{
				ih = (ip_v4_header*)p;
			}
			offset = (byte)(ih->ver_ihl & 0xf)*4;
			rih = *ih;
			return rih;
		}
		public unsafe ip_v6_header Ip_V6_Package_Getter()
		{
			ip_v6_header rih = new ip_v6_header();
			ip_v6_header* ih;
			fixed (byte* p = &_ph.pkt_data[14])
			{
				ih = (ip_v6_header*)p;
			}
			offset = 40;
			rih = *ih;
			return rih;
		}
		public unsafe udp_header Udp_Package_Getter()
		{
			udp_header ruh = new udp_header();
			udp_header* uh;
			offset = offset + 14;
			fixed (byte* p = &_ph.pkt_data[offset])
			{
				uh = (udp_header*)p;
			}
			isDataComp = true;
			offset = offset + 8;
			ruh = *uh;
			return ruh;
		}
		public unsafe tcp_header Tcp_Package_Getter()
		{
			tcp_header rth = new tcp_header();
			tcp_header* th;
			offset = offset + 14;
			fixed (byte* p = &_ph.pkt_data[offset])
			{
				th = (tcp_header*)p;
			}
			isDataComp = true;
			offset = offset + th->offset * 4;
			rth = *th;
			return rth;
		}
		public unsafe icmp_header Icmp_Package_Getter()
		{
			icmp_header rih = new icmp_header();
			icmp_header* ih;
			offset = offset + 14;
			fixed (byte* p = &_ph.pkt_data[offset])
			{
				ih = (icmp_header*)p;
			}
			rih = *ih;
			return rih;
		}
	}
}
