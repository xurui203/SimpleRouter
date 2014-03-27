#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_packet_builder.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"


/*
 * Class for building icmp, ip and arp packets
 */

/* NEED TO:

	- Build ethernet frame
	- Build IP packet
	- build icmp packets:
		t0 (echo reply)
		t3_c0 (destination net unreachable)
		t3_c1 (destination host unreachable)
		t3_c3 (port unreachable)
		t11_c0 (time exceeded)
*/



/*Builds ARP packet*/

#define PROTOCOL_ADDR_LEN 4 /*IPv4 address length is 4*/
uint8_t* generate_ip_packet(uint32_t source, uint32_t dest, uint8_t *payload, int payload_size){
	uint8_t* ip;
	struct sr_ip_hdr* header=malloc(sizeof(struct sr_ip_hdr)+payload_size);

	header->ip_hl=(sizeof(struct sr_ip_hdr)/4);
	header->ip_v=4;
	header->ip_tos=0;
	header->ip_id=htons(0);
	header->ip_off=0;
	header->ip_ttl=64;
	header->ip_p=ip_protocol_icmp;
	header->ip_src=(source);
	header->ip_dst=(dest);
	header->ip_sum=0;
	uint16_t pkt_len = sizeof(sr_ip_hdr_t) + (sizeof(uint8_t) * payload_size);
	header->ip_len = htons(pkt_len);
	header->ip_sum= cksum(header,sizeof(struct sr_ip_hdr));
	ip=malloc(pkt_len);
	/*memcpy(header+sizeof(struct sr_ip_hdr),payload,payload_size);*/
	memcpy(ip,header,sizeof(struct sr_ip_hdr));
	memcpy(ip + sizeof(sr_ip_hdr_t), payload, payload_size);
	/* Need to convert to network and back for checksum calculations?*/
	return ip;
}

uint8_t* generate_arp_packet(unsigned short ar_op, unsigned char ar_sha[], uint32_t ar_sip, const unsigned char ar_tha[], uint32_t ar_tip){
	uint8_t* arp;
	struct sr_arp_hdr header;
	header.ar_hrd = htons(arp_hrd_ethernet); /*hardware address*/
	header.ar_pro = htons(ethertype_ip); /*protocol address*/
	header.ar_hln = ETHER_ADDR_LEN; /* hardware address length = 6*/
	header.ar_pln = PROTOCOL_ADDR_LEN; /* protocol (IPv4) address length = 4*/
	header.ar_op = ar_op; /*ARP opcode*/
	memcpy(header.ar_sha, ar_sha, ETHER_ADDR_LEN); /*sender hardware address*/
	header.ar_sip = ar_sip; /*sender IP address*/
	memcpy(header.ar_tha, ar_tha, ETHER_ADDR_LEN);
	header.ar_tip = ar_tip;
	arp = (uint8_t*) malloc (sizeof (header));
	memcpy (arp, &header, sizeof(header));
	return arp;
}


/*
 * Builds ethernet frame with MAC HEADER (Dest MAC address, Source MAC address, EtherType) - PAYLOAD (IP/ ARP)
 */

uint8_t* generate_ethernet_frame(uint8_t *ether_dhost, uint8_t *ether_shost, uint16_t ether_type, uint8_t *payload, int payload_size ){ /*payload is IP/ARP*/
	uint8_t *frame;
	struct sr_ethernet_hdr *header=malloc(sizeof(struct sr_ethernet_hdr));
	memcpy(header->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
	memcpy(header->ether_shost, ether_shost, ETHER_ADDR_LEN);
	header->ether_type = ether_type;
	frame = malloc (sizeof (struct sr_ethernet_hdr) + sizeof(uint8_t) * payload_size);
	memcpy(frame, header, sizeof(struct sr_ethernet_hdr));
	memcpy(frame + sizeof(struct sr_ethernet_hdr), payload, payload_size);

	return frame;
}

uint8_t* generate_icmp_frame(uint8_t type, uint8_t code, uint8_t* payload, int payload_size){
	uint8_t *frame;
	struct sr_icmp_hdr *header=malloc(sizeof(struct sr_icmp_hdr)+payload_size);
	header->icmp_type=type;
	header->icmp_code=code;
	header->icmp_sum=0;
	/*header->icmp_sum=cksum((header),sizeof(struct sr_icmp_hdr));*/
	frame=malloc(sizeof(struct sr_icmp_hdr)+payload_size);
	memcpy(frame,header,sizeof(struct sr_icmp_hdr));
	memcpy(frame+sizeof(sr_icmp_hdr_t),payload,payload_size);
	((sr_icmp_hdr_t*)(frame))->icmp_sum=cksum(frame,sizeof(sr_icmp_hdr_t)+payload_size);
	return frame;
}

uint8_t* generate_icmp_3_frame( uint8_t code,uint8_t* data){
	uint8_t *frame;
	struct sr_icmp_t3_hdr header;
	header.icmp_type=3;
	header.icmp_code=code;
	memcpy(header.data,data,ICMP_DATA_SIZE);
	header.next_mtu=0;
	header.icmp_sum=0;
	header.icmp_sum=cksum((void *)(&header),sizeof(struct sr_icmp_t3_hdr));
	frame=(uint8_t*) malloc(sizeof(header));
	memcpy(frame,&header,sizeof(header));
	return frame;
}
