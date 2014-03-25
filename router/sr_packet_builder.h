/*
 * sr_packet_builder.h
 *
 *  Created on: Mar 24, 2014
 *      Author: XuRui
 */

#ifndef SR_PACKET_BUILDER_H_
#define SR_PACKET_BUILDER_H_

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

uint8_t* generate_arp_packet(unsigned short ar_op, unsigned char ar_sha[], uint32_t ar_sip, const unsigned char ar_tha[], uint32_t ar_tip);


uint8_t* generate_ethernet_frame(uint8_t *ether_dhost, uint8_t *ether_shost, uint16_t ether_type, uint8_t *payload, int payload_size );

uint8_t* generate_icmp_frame(uint8_t type, uint8_t code);

uint8_t* generate_icmp_3_frame(uint8_t type, uint8_t code,uint8_t data[28]);


#endif /* SR_PACKET_BUILDER_H_ */
