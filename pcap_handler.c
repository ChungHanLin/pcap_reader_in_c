#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "header.h"

#define BUFF_SIZE 1024

void packet_Handler(u_char *, const struct pcap_pkthdr*, const u_char*);
char *getTimeString(time_t);

static int dataLength;

int main(int argc, char **argv){
	int i = 0;
	char errorBuff[BUFF_SIZE];
	char enterFilter[128] = "";
	const char *filter = "";
	struct bpf_program fcode;

	pcap_t *pcapFD = pcap_open_offline(argv[1], errorBuff);

	// open file fail
	if(!pcapFD){
		fprintf(stderr, "%s\n", errorBuff);
		exit(EXIT_FAILURE);
	}
	printf("Open file successfully\n\n");

	dataLength = 0;	// 計算接收 data 數

	// set fileter (設定過濾方式)
	if(argc >= 3){
		for(i = 2; i < argc; i++){
			strcat(enterFilter, argv[i]);
			if(i == argc - 1){
				strcat(enterFilter, "\0");
			}
			else{
				strcat(enterFilter, " ");
			}
		}
		filter = enterFilter;
	}


	if(pcap_compile(pcapFD, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN) < 0){
		fprintf(stderr, "%s\n", pcap_geterr(pcapFD));
		pcap_close(pcapFD);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(pcapFD, &fcode) < 0){
		fprintf(stderr, "%s\n", pcap_geterr(pcapFD));
		pcap_close(pcapFD);
		exit(EXIT_FAILURE);
	}

	if((pcap_loop(pcapFD, 0, packet_Handler, NULL)) < 0){
		fprintf(stderr, "%s\n", pcap_geterr(pcapFD));
		pcap_close(pcapFD);
		exit(EXIT_FAILURE);
	}
	// print out if the whole file has been processed
	printf("Catured Data: %d\nfinish!\n", dataLength);

	// close the pcap file if ended
	pcap_close(pcapFD);
	return 0;
}

// header 中存放 pcap 大小、時間訊息
// packet 則存放整個結構
void packet_Handler(u_char *pcapFD, const struct pcap_pkthdr* header, const u_char* packet){
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;		
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	const struct sniff_icmp *icmp;

	int size_ethernet = sizeof(struct sniff_ethernet);
	int size_ip = sizeof(struct sniff_ip);
	int size_tcp = sizeof(struct sniff_tcp);
	int size_udp = sizeof(struct sniff_udp);
	int size_icmp = sizeof(struct sniff_icmp);

	char portBuffer[BUFF_SIZE] = "";	// try if not added

	dataLength++;

	// 定義 header pointer
	ethernet = (struct sniff_ethernet *) packet;
	ip = (struct sniff_ip *) (packet + size_ethernet);

	switch(ip->ip_p){
	
	case IPPROTO_TCP:
		tcp = (struct sniff_tcp *) (packet + size_ethernet + size_ip);
		
		printf("%d. TCP\n", dataLength);
		sprintf(portBuffer, "%sSource Port : %d\n", portBuffer, ntohs(tcp->th_sport));
		sprintf(portBuffer, "%sTarget Port : %d\n", portBuffer, ntohs(tcp->th_dport));
		break;

	case IPPROTO_UDP:
		udp = (struct sniff_udp *) (packet + size_ethernet + size_ip);
		
		printf("%d. UDP\n", dataLength);
		sprintf(portBuffer, "%sSource Port : %d\n", portBuffer, ntohs(udp->uh_sport));
		sprintf(portBuffer, "%sTarget Port : %d\n", portBuffer, ntohs(udp->uh_dport));

		break;
	
	case IPPROTO_ICMP:
		icmp = (struct sniff_icmp *) (packet + size_ethernet + size_ip);
		
		printf("%d. ICMP\n", dataLength);

		break;

	case IPPROTO_IP:
		printf("Protocol : IP\n");
		return;

	default:
		dataLength--;
		return;
	
	}

	// inet_ntoa : return address String with "." notation
	printf("Length : %d\n", header->len);
	printf("Time : %s\n", getTimeString(header->ts.tv_sec));
	printf("Source IP : %s\n", inet_ntoa(ip->ip_src));
	printf("Target IP : %s\n", inet_ntoa(ip->ip_dst));
	printf("%s\n", portBuffer);

//	printf("Source Port : %d\n", ntohs(tcp->th_sport));
//	printf("Target Port : %d\n\n", ntohs(tcp->th_dport));

}

char *getTimeString(time_t capturedTime){
	struct tm *ltime;
	char timeString[64];
	char *timePtr;
	time_t time = capturedTime;

	ltime = localtime(&time);
	strftime(timeString, sizeof timeString, "%F %H:%M:%S", ltime);

	timePtr = timeString;

	return timePtr;
}
