/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_packet_builder.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);



	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/*
  //build outgoing payload

   	   if incoming packet is ethernet packet,
   	   	   process IP payload
   	   	   set outgoing_packet_type to IP

   	   if incoming packet is ARP packet
   	   	   process ARP payload
   	   	   set outgoing_packet_type to ARP


  //build and send outgoing ethernet frame
 *  Sanity check packet (meets minimum length and has correct checksum)
  	  Decrement TTL by 1, recompute packet checksum over modified header
  	  Find out which entry in routing table has longest prefix match with destination IP address
  	  Check ARP cache for next-hop MAC address corresponding to next-hop IP.
  	  If there, send it.
  	  If not, send ARP request to next-hop IP.
  	  Add packet to the queue of packets waiting on the ARP request.
 *
 * Pseudocode:
    	# When sending packet to next_hop_ip
   	   	  entry = arpcache_lookup(next_hop_ip)
   	      if entry:
       	   	  use next_hop_ip->mac mapping in entry to send the packet
       	   	  free entry
   	   	  else:
       	   	  req = arpcache_queuereq(next_hop_ip, packet, len)
       	   	  handle_arpreq(req)

 */
void sr_handlepacket(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */)
{

	/*
		struct sr_ethernet_hdr* incoming_ethernet_packet;
		outgoing_ethernet_packet
		outgoing_ethernet_packet_length
		outgoing_destination_IP
		outgoing_ethernet_payload
		outgoing_ethernet_payload_length
		outgoing_client_MAC
		outgoing_packet_type

	 */


	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	/* Check for minimum length*/
	if ( len < sizeof(struct sr_ethernet_hdr) ){
		fprintf(stderr , "** Error: packet is too short \n");
		return;
	}

	uint16_t packet_type= ethertype(packet);

	if (packet_type==ethertype_ip){
		sr_handleip(sr,packet,len,interface);
	}
	if (packet_type==ethertype_arp){
		sr_handlearp(sr,packet,len,interface);
	}

	return;

}/* end sr_ForwardPacket */

/* Process IP payload:

if IP packet destined for one of router's IP addresses:

	  if packet is an ICMP echo request and checksum is valid:
	  		send ICMP echo reply to sending
	  if packet contains a TCP or UDP payload
	  		send an ICMP port unreachable (t0) to the sending host.
	  else
	  		ignore packet.

 else if packets destined elsewhere
 	  should be forwarded using normal forwarding logic:


 *
 */
void sr_handleip(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */){
	printf("IP Packet\n");
	/* Check for corruption */
	if (len<sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)){
		printf("Error: IP packet is too short");
		return;
	}
	/*print_hdrs(packet,len);*/
	sr_icmp_hdr_t* icmp=(sr_icmp_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	int check=icmp->icmp_sum;
	icmp->icmp_sum=0;
	printf("Calc is: %d, actual is: %d, size is: %d, calc_size is: %d\n",cksum(icmp,sizeof(sr_icmp_hdr_t)+60),check,len,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t));
	icmp->icmp_sum=check;
	print_hdr_icmp(packet+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t checksum=ip_header->ip_sum;
	ip_header->ip_sum=0;
	if (cksum(ip_header,sizeof(sr_ip_hdr_t))!=checksum){
		printf("Error: IP checksum does not match packet %d, %d\n",checksum,(cksum(ip_header,sizeof(sr_ip_hdr_t))));
		return;
	} else {
		printf("IP Checksum match\n");
	}
	struct sr_ethernet_hdr* ether_hdr=(struct sr_ethernet_hdr*)(packet);
	/* Check if the destination IP matches an interface */
	struct sr_if* inter=sr->if_list;
	struct sr_if* is_match=sr_checkinterfaces(inter,ip_header->ip_dst);
	if (is_match){
		/* If so, handle ICMP response */
		printf("IP packet for me\n");
		if (ip_header->ip_p==ip_protocol_icmp){
			printf("It's icmp!\n");
			sr_icmp_hdr_t* icmp_hdr=(sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			icmp_hdr->icmp_sum=0;
			if (icmp_hdr->icmp_type==8 && cksum(icmp_hdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t))){
				printf("Sending a reply\n");
				uint8_t *icmp_reply = generate_icmp_frame(0, 0,packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t),len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t)); /* TODO */
				printf("icmp checksum is: %d\n",((sr_icmp_hdr_t*)(icmp_reply))->icmp_sum);
				uint8_t *ip_packet = generate_ip_packet(is_match->ip,ip_header->ip_src,icmp_reply,sizeof(struct sr_icmp_hdr)+len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t));
				print_hdr_icmp(ip_packet+(sizeof(struct sr_ip_hdr)));
				uint8_t *ether_packet=generate_ethernet_frame(ether_hdr->ether_dhost, ether_hdr->ether_shost, htons(ethertype_ip), ip_packet, sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_hdr)+len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t) );
				print_hdrs(ether_packet,len);
				sr_find_dest(sr, ip_header->ip_src, ether_packet,len, is_match->addr, (char*)(is_match->name),0);
			}
		} else {
			printf("UDP or TCP Packet, can't handle this\n");
			struct sr_packet* pack=malloc(sizeof(struct sr_packet));
			pack->buf=packet;
			pack->iface=interface;
			pack->len=sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_t3_hdr);
			pack->next=NULL;

			sr_send_icmp_3(sr, pack, 3);
		}
	}
	else{
		/* Not for me, passing it on */
		printf("No IP match in interfaces, checking routing table\n");
		ip_header->ip_ttl-=1;
		if (ip_header->ip_ttl==0){
			printf("Time's up!\n");
			uint8_t *icmp_error=generate_icmp_frame(11,0,(uint8_t*)(ip_header),sizeof(sr_ip_hdr_t)+8);
			struct sr_if* inter=sr_get_interface(sr,interface);
			uint8_t *ip_packet=generate_ip_packet(inter->ip,ip_header->ip_src,icmp_error,sizeof(struct sr_icmp_hdr));
			uint8_t *ether_packet=generate_ethernet_frame(ether_hdr->ether_shost,ether_hdr->ether_dhost, htons(ethertype_ip), ip_packet, sizeof(struct sr_icmp_hdr)+sizeof(struct sr_ip_hdr) );
			print_hdrs(packet,len);
			printf("Size is: %d\n",sizeof(struct sr_ethernet_hdr));
			print_hdrs(ether_packet,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_hdr));
			int is_sent=sr_send_packet(sr,ether_packet,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_hdr),interface);
			/*sr_find_dest(sr,inter->ip,ether_packet,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_hdr),ether_hdr->ether_dhost,interface,0);*/
			return;
		}
		ip_header->ip_sum=0;
		ip_header->ip_sum=cksum(ip_header,sizeof(sr_ip_hdr_t));
		struct sr_ethernet_hdr* ethernet_header=(struct sr_ethernet_hdr*)(packet);
		sr_find_dest(sr, ip_header->ip_dst,packet, len, ethernet_header->ether_dhost,interface,1);
	}
}

/*
 Process ARP payload
	if ARP reply, cache entry if target IP is router's IP address.

	if ARP request, send ARP reply to reuester's MAC address if target IP is router's IP address.

 */
void sr_handlearp(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */){
	printf("ARP Packet\n");
	/*print_hdrs(packet,len);*/
	struct sr_if* inter=sr->if_list;
	sr_arp_hdr_t *arp_header=(sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
	struct sr_if *is_match=sr_checkinterfaces(inter,arp_header->ar_tip); /* Checks interfaces for IP match, returns 1 for success, 0 for fail */
	/* If success, matching interface is stored in inter */
	if (ntohs(arp_header->ar_op)==arp_op_request){
		/* If arp request, see if it is for me */
		printf("ARP Request\n");
		/*fprintf(stderr,"Desired IP is: %d, is found: %d\n",arp_header->ar_tip, is_mine);*/
		if(is_match){
			/* If so, send a reply */
			/*sr_print_if(inter);*/
			int sent=sr_sendarpreply(sr,interface,is_match->ip,is_match->addr,arp_header->ar_sip,arp_header->ar_sha);
			fprintf(stderr,"Was sent: %d",sent);
		}
		/* Else, ignore */
	}
	if (ntohs(arp_header->ar_op)==arp_op_reply){
		/* If it is an arp reply */
		printf("ARP Reply\n");
		if (is_match){
			printf("ARP reply for me??\n");
			struct sr_arpreq *req=sr_arpcache_insert(&sr->cache,arp_header->ar_sha,arp_header->ar_sip);
			int i=0;
			for (i=0;i<ETHER_ADDR_LEN;i++){
				printf("%c",arp_header->ar_sha[i]);
			}
			print_addr_ip_int(arp_header->ar_sip);
			if (req){
				printf("We were looking for this!\n");
				struct sr_packet* packet=req->packets;
				do {
					printf("Be free IP packets!\n");
					sr_ethernet_hdr_t *ether=(struct sr_ethernet_hdr*)(packet->buf);
					memcpy(ether->ether_dhost,arp_header->ar_sha,ETHER_ADDR_LEN);
					memcpy(ether->ether_shost,arp_header->ar_tha,ETHER_ADDR_LEN);
					ether->ether_type=htons(ethertype_ip);
					/*print_hdrs(packet->buf,packet->len);*/
					printf("That was the packet we were sending!\n");
					int is_sent=sr_send_packet(sr,packet->buf,packet->len,interface);
					if (is_sent){
						printf("And it was sent!\n");
						sr_arpreq_destroy(&sr->cache,req);
					}
				} while ((packet=packet->next));
			}
		}
	}
}

void sr_find_dest(struct sr_instance* sr, uint32_t dest, uint8_t* packet, unsigned int len, uint8_t* shost, char* interface,int getvals){
	struct sr_rt *routing_table=sr->routing_table;
	struct sr_rt* routing_match = sr_checkroutingtable(routing_table,dest);
	if (routing_match) {
		print_hdrs(packet,len);
		/* Only pass on if the next IP is in the routing table */
		printf("Routing match for IP, checking ARP cache\n");
		/*sr_arpcache_dump(&sr->cache);*/
		/* See if we have the MAC address in the arpcache */
		struct sr_arpentry * arp_entry= sr_arpcache_lookup(&sr->cache,(routing_match)->dest.s_addr);
		printf("Checked arp cache\n");
		if (arp_entry){
			/* If so, send packet */
			printf("Arp cache match, sending packet on\n");
			printf("getvals: %d\n",getvals);
			struct sr_ethernet_hdr* ethernet_header=(struct sr_ethernet_hdr*)(packet);
			/*if (getvals){*/
				interface=routing_match->interface;
				struct sr_if* inter=sr_get_interface(sr, interface);
				shost=inter->addr;
			/*}*/
			memcpy(ethernet_header->ether_shost,shost,6);
			memcpy(ethernet_header->ether_dhost,(uint8_t*)(arp_entry->mac),6);
			ethernet_header->ether_type=htons(ethertype_ip);
			/*print_hdrs(packet,len);*/
			printf("Interface is: %s, the routing match is: %s",interface,routing_match->interface);
			int is_sent=sr_send_packet(sr,packet,len,routing_match->interface);
			print_hdrs(packet,len);
			printf("Sent: %d\n",is_sent);
		} else {
			/* If no arpcache match, send arp request */
			printf("No cache hit, sending arp_request\n");
			print_hdrs(packet,len);
			printf("Interface is: %s, routing match interface is: %s",interface,routing_match->interface);
			struct sr_arpreq * arp_request=sr_arpcache_queuereq(&sr->cache,(routing_match)->dest.s_addr,packet,len,(routing_match)->interface);
		}
	} else {
		struct sr_packet* pack=malloc(sizeof(struct sr_packet*));
		pack->buf=packet;
		pack->iface=interface;
		pack->len=sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_t3_hdr);
		pack->next=NULL;
		sr_send_icmp_3(sr, pack, 0);
	}
}

struct sr_if* sr_checkinterfaces(struct sr_if* interface, uint32_t target_ip){
	do {
		/*printf("my interface ip is: \n");
		print_addr_ip_int(ntohl(interface->ip));
		printf("target_ip is: \n");
		print_addr_ip_int(ntohl(target_ip));*/
		if (interface->ip==target_ip) return interface;
	} while ((interface=interface->next));
	return NULL;
}

struct sr_rt* sr_checkroutingtable(struct sr_rt* routing_table, uint32_t target_ip){
	do{
		/*printf("my rt ip is: \n");
		print_addr_ip_int(ntohl(routing_table->dest.s_addr & routing_table->mask.s_addr));
		printf("target_ip is: \n");
		print_addr_ip_int(ntohl(target_ip & routing_table->mask.s_addr));*/
		if (routing_table->dest.s_addr & routing_table->mask.s_addr & target_ip & routing_table->mask.s_addr) {
			printf("Routing table match!\n");
			return routing_table;
		}
	} while ((routing_table=routing_table->next));
	return NULL;
}

int sr_sendarpreply(struct sr_instance* sr, const char* iface, uint32_t ar_sip,unsigned char ar_sha[],uint32_t ar_tip,unsigned char ar_tha[]){
	uint8_t* arp_packet=generate_arp_packet(htons(arp_op_reply), ar_sha, ar_sip, ar_tha, ar_tip);
	uint8_t* ether_packet=generate_ethernet_frame(ar_tha,ar_sha,htons(ethertype_arp),arp_packet,sizeof(sr_arp_hdr_t));
	/*print_hdrs(ether_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));*/
	int success= sr_send_packet(sr,ether_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t),iface);

	return success;
}
