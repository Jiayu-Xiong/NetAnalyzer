#include "Zixpcap.h"
#include "pch.h"
#include <iostream>
using namespace std;
using std::string;
extern "C" _declspec(dllexport) void init_device(char* args);
extern "C" _declspec(dllexport) void reset(void);
extern "C" _declspec(dllexport) int get_length(void);
extern "C" _declspec(dllexport) void get_package(struct pcap_pkthdr* pht,  unsigned char* pkt_data, int len);
extern "C" _declspec(dllexport) void get_args_safe(int package);
extern "C" _declspec(dllexport) bool init_args(int dev);
extern "C" _declspec(dllexport) int get_package_length(void);
void ShowNote(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	MessageBox(NULL, r.c_str(), L"A Error", MB_OK);
}
void Replacer(string& inside, const string& FindChar, const string& ReplaceChar)
{
	string::size_type pos = 0;
	string::size_type a = FindChar.size();
	string::size_type b = ReplaceChar.size();
	while ((pos = inside.find(FindChar, pos)) != string::npos)
	{
		inside.replace(pos, a, ReplaceChar);
		pos += b;
	}
}

/* IP计数器 */
std::map<std::string, int> counter;
#include<list>
struct PackageHandle {
	struct pcap_pkthdr header;
	u_char* pkt_data;
};
static list<PackageHandle> marray;
static list<int> sarray;

/* 网络协议结构体 */
struct ip_v4_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

struct ip_v6_address
{
	u_short part1;
	u_short part2;
	u_short part3;
	u_short part4;
	u_short part5;
	u_short part6;
	u_short part7;
	u_short part8;
};

struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
};

struct ethernet_header
{
	mac_address des_mac_addr;
	mac_address src_mac_addr;
	u_short type;
};

struct ip_v4_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short checksum;			// Header checksum
	ip_v4_address	src_ip_addr;		// Source address
	ip_v4_address	des_ip_addr;		// Destination address
	u_int	op_pad;			// Option + Padding
};

struct ip_v6_header
{
	u_int32_t ver_trafficclass_flowlabel;
	u_short payload_len;
	u_char next_head;
	u_char ttl;
	ip_v6_address src_ip_addr;
	ip_v6_address dst_ip_addr;
};

struct arp_header
{
	u_short hardware_type;
	u_short protocol_type;
	u_char hardware_length;
	u_char protocol_length;
	u_short operation_code;
	mac_address source_mac_addr;
	ip_v4_address source_ip_addr;
	mac_address des_mac_addr;
	ip_v4_address des_ip_addr;
};

struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int sequence;
	u_int acknowledgement;
	u_char offset;
	u_char flags;
	u_short windows;
	u_short checksum;
	u_short urgent_pointer;
};

struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short checksum;			// Checksum
};

struct icmp_header
{
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short sequence;
};
static bool IsOpen = false;
static pcap_t* mainhandle = nullptr;
void reset(void)
{
	if (mainhandle) {
		pcap_breakloop(mainhandle);
		marray.clear();
		sarray.clear();
	}
}
void get_args_safe(int package)
{
	pcap_loop(mainhandle, package, packet_handler, NULL);
}
bool init_args(int dev)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask = 0xffffff;;
	struct bpf_program fcode;
	pcap_findalldevs(&alldevs, errbuf);
	for (d = alldevs, i = 0; i < dev - 1; d = d->next, i++);
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		pcap_freealldevs(alldevs);
		return false;
	}
	pcap_freealldevs(alldevs);
	if (pcap_compile(adhandle, &fcode, "ip or arp", 1, netmask) < 0)
	{
		pcap_close(adhandle);
		return false;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		pcap_close(adhandle);
		return false;
	}
	mainhandle = adhandle;
	IsOpen = true;
	return true;
}
int get_length(void)
{
	return marray.size();
}
void init_device(char* args)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int circ = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask = 0xffffff;;
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		const std::string var = errbuf;
		const std::string msg = "A Error while finding network card:" + var;
		ShowNote(msg);
		exit(1);
	}
	int i = 0;
	char endl[] = "\n";
	for (d = alldevs; d; d = d->next)
	{
		++circ;
		if (d->description)
		{
			string Objx = d->description;
			int length = Objx.length();
			memcpy(args + i, d->description, length);
			i += length;
			memcpy(args + i++, endl, 1);
		}
		else
			ShowNote("A network card lacks name");
	}
	if (circ == 0)
	{
		ShowNote("No available network card");
	}
	args[i] = '\0';
	return;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	PackageHandle ph;
	ph.header = *header;
	ph.pkt_data = new u_char[header->len];
	memcpy(ph.pkt_data, pkt_data, header->len);
	//ph.pkt_data = pkt_data;
	sarray.push_back(header->len);
	marray.push_back(ph);
}
static bool IsAllowed=false;
int get_package_length(void)
{
	if (!sarray.empty())
	{
		IsAllowed = true;
		int obj = sarray.front();
		sarray.pop_front();
		return obj;
	}
	return 0;
}
void get_package(struct pcap_pkthdr* pht,unsigned char* pkt_data,int len)
{
	if (!marray.empty()&&IsAllowed)
	{
		PackageHandle ph = marray.front();
		memcpy(pkt_data, ph.pkt_data, len);
		*pht = ph.header;
		marray.pop_front();
	}
	else if (!marray.empty())
	{
		marray.front();
		IsAllowed=true;
	}
}
void add_to_map(map<string, int>& counter, ip_v4_address ip)
{
	string ip_string;
	int amount = 0;
	map<string, int>::iterator iter;
	ip_string = to_string(ip.byte1) + "."
		+ to_string(ip.byte2) + "."
		+ to_string(ip.byte3) + "."
		+ to_string(ip.byte4);
	iter = counter.find(ip_string);
	if (iter != counter.end())
	{
		amount = iter->second;
	}
	counter.insert_or_assign(ip_string, ++amount);
}

void add_to_map(map<string, int>& counter, ip_v6_address ip)
{
	string ip_string;
	int amount = 0;
	map<string, int>::iterator iter;
	ip_string = to_string(ip.part1) + ":"
		+ to_string(ip.part2) + ":"
		+ to_string(ip.part3) + ":"
		+ to_string(ip.part4) + ":"
		+ to_string(ip.part5) + ":"
		+ to_string(ip.part6) + ":"
		+ to_string(ip.part7) + ":"
		+ to_string(ip.part8);
	iter = counter.find(ip_string);
	if (iter != counter.end())
	{
		amount = iter->second;
	}
	counter.insert_or_assign(ip_string, ++amount);
}

void print_map(map<string, int> counter)
{
	map<string, int>::iterator iter;
	cout << DIVISION << "Flow statistics" << DIVISION << endl;
	cout << "IP" << setfill(' ') << setw(45) << "Flow" << endl;
	for (iter = counter.begin(); iter != counter.end(); iter++)
	{
		cout << iter->first << setfill('.') << setw(45 - iter->first.length()) << iter->second << endl;
	}
}
