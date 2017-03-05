//要把头文件和库文件包含进项目里，并在主文件中引用库#pragma comment(lib,"wpcap.lib")
#ifndef MYPC
#define MYPC
#include<stdlib.h>
#include<iostream>
#include<pcap.h>
#include<remote-ext.h>
#include<Win32-Extensions.h>
int pcap_1();
void packet_handler_3(u_char *param, const struct pcap_pkthdr *header, const u_char*pkt_data);
int pcap_3();
int pcap_4();//read packet by pcap_next_ex
struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};
struct ip_header
{
	u_char ver_ihl;//version(4bits)+header length(4bits) 8bits
	u_char tos;//type of service 8bits
	u_short tlen;//total of length 16bits
	u_short identification; //Identification 16bits
	u_short flags_fo;// flags 3bits+fragment offset(13bits)
	u_char ttl;//time to live(8bits)
	u_char pro;//protocal
	u_short hc;//header checksum
	ip_address saddr;//source IP address
	ip_address daddr;//destination IP address
	u_int op_pa;
};
struct udp_header
{
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
};
void packet_handler_6(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data);
int pcap_6();
/* prototype of the packet handler */
void packet_handler_7_1(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int pcap_7_1();// save packet to file 
void packet_handler_7_2(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int pcap_7_2();//read packet from file
void pcap_self();
void packet_handler_self(u_char *, const struct pcap_pkthdr*, const u_char *);
void pcap_8();//sending a packet
void packet_handler_9(u_char *, const struct pcap_pkthdr*, const u_char *);
void pcap_9();
#endif
