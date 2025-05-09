#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

 /*引入环境静态库*/
#define WIN32
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib")

/* C++ */
#include <iostream>
#include <stdio.h>
#include <map>
#include <string>
#include <iomanip>
#include <sstream>

/*WPCAP*/
#include <pcap.h>
#include <WinSock2.h>


#define DIVISION "--------------------"
#define B_DIVISION "==================="


 /* 4 bytes IP address */
typedef struct ip_v4_address ip_v4_address;

/* 16 bytes IP address */
typedef struct ip_v6_address ip_v6_address;

/*8 bytes MAC addresss*/
typedef struct mac_address mac_address;

/*ethernet header*/
typedef struct ethernet_header ethernet_header;

/* IPv4 header */
typedef struct ip_v4_header ip_v4_header;

/*IPv6 header*/
typedef struct ip_v6_header ip_v6_header;

/*arp header*/
typedef struct arp_header arp_header;

/*TCP header*/
typedef struct tcp_header tcp_header;

/* UDP header*/
typedef struct udp_header udp_header;

/*ICMP header*/
typedef struct icmp_header icmp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

/*count the package with c++ std::map*/
void add_to_map(std::map<std::string, int>& counter, ip_v4_address ip);
void add_to_map(std::map<std::string, int>& counter, ip_v6_address ip);

/*print the map info*/
void print_map(std::map<std::string, int> counter);
