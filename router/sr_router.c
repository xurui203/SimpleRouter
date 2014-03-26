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
	  sr_handleip(sr,packet,len-sizeof(sr_ethernet_hdr_t),interface);
  }
  if (packet_type==ethertype_arp){
	  sr_handlearp(sr,packet,len-sizeof(sr_ethernet_hdr_t),interface);
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
	if (len<sizeof(sr_ip_hdr_t)){
		printf("Error: IP packet is too short");
		return;
	}
	print_hdrs(packet,len);
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t checksum=ip_header->ip_sum;
	ip_header->ip_sum=0;
	if (cksum(ip_header,sizeof(sr_ip_hdr_t))!=checksum){
		printf("Error: IP checksum does not match packet %d, %d\n",checksum,(cksum(ip_header,sizeof(sr_ip_hdr_t))));
		return;
	} else {
		printf("IP Checksum match\n");
	}
	/* Check if the destination IP matches an interface */
	int is_match=sr_checkinterfaces(sr->if_list,ip_header->ip_dst);
	if (is_match){
		/* If so, handle ICMP response */
		printf("IP packet for me\n");
		if (ip_header->ip_p==ip_protocol_icmp){
			struct sr_icmp_hdr* icmp_hdr=ip_header+sizeof(struct sr_ip_hdr);
			if (icmp_hdr->icmp_type==8){
				uint8_t *icmp_reply = generate_icmp_frame(0, 0);

				/*TODO Handle ICMP*/
			}
		}
		if (!is_match){
			/* Not for me, passing it on */
			printf("No IP match in interfaces, checking routing table\n");
			ip_header->ip_ttl-=1;
			if (ip_header->ip_ttl=0){
				/*TODO send imcp*/
				return;
			}
			ip_header->ip_sum=0;
			ip_header->ip_sum=cksum(ip_header,sizeof(sr_ip_hdr_t));
			/* Check routing table for next hop */
			struct sr_rt* routing_table=sr->routing_table;
			int routing_match = sr_checkroutingtable(routing_table,ip_header->ip_dst);
			if (routing_match) {
				/* Only pass on if the next IP is in the routing table */
				printf("Routing match for IP, checking ARP cache\n");
				sr_arpcache_dump(&sr->cache);
				/* See if we have the MAC address in the arpcache */
				struct sr_arpentry * arp_entry= sr_arpcache_lookup(&sr->cache,routing_table->dest.s_addr);
				printf("Checked arp cache\n");
				if (arp_entry){
					/* If so, send packet */
					printf("Arp cache match, sending packet on\n");
					struct sr_ethernet_hdr* ethernet_header=(struct sr_ethernet_hdr*)(packet);
					memcpy(ethernet_header->ether_shost,ethernet_header->ether_dhost,6);
					memcpy(ethernet_header->ether_dhost,(uint8_t)(arp_entry->mac),6);
					int is_sent=sr_send_packet(sr,packet,len,interface);
					free(arp_entry);
					printf("Sent: %d\n",is_sent);
				} else {
					/* If no arpcache match, send arp request */
					printf("No cache hit, sending arp_request\n");
					struct sr_arpreq * arp_request=sr_arpcache_queuereq(&sr->cache,routing_table->dest.s_addr,packet,len,routing_table->interface);
				}
			}
		}
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
	print_hdrs(packet,len);
	struct sr_if* inter=sr->if_list;
	sr_arp_hdr_t *arp_header=(sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
	int is_mine=sr_checkinterfaces(inter,arp_header->ar_tip); /* Checks interfaces for IP match, returns 1 for success, 0 for fail */
	/* If success, matching interface is stored in inter */
	if (ntohs(arp_header->ar_op)==arp_op_request){
		/* If arp request, see if it is for me */
		printf("ARP Request\n");
		/*fprintf(stderr,"Desired IP is: %d, is found: %d\n",arp_header->ar_tip, is_mine);*/
		if(is_mine==1){
			/* If so, send a reply */
			/*sr_print_if(inter);*/
			int sent=sr_sendarpreply(sr,interface,inter->ip,inter->addr,arp_header->ar_sip,arp_header->ar_sha);
			fprintf(stderr,"Was sent: %d",sent);
		}
		/* Else, ignore */
	}
	if (ntohs(arp_header->ar_op)==arp_op_reply){
		/* If it is an arp reply */
		printf("ARP Reply\n");
		if (is_mine){
			/* Matches interface IP
			 * arpcache is in sr->cache
			 * Go through arpreq list, check for match
			 * If match, pull packet and arpreq from list, send packet
			 * */
		}
		/* Will Add to arpcache*/
	}
}

int sr_checkinterfaces(struct sr_if* interface, uint32_t target_ip){
	if (interface->ip==target_ip) return 1;
	while ((interface->next)!=NULL){
		printf("my interface ip is: %d, target_ip is: %d\n",interface->ip,target_ip);
		interface=interface->next;
		if (interface->ip==target_ip) return 1;
	}
	return 0;
}

int sr_checkroutingtable(struct sr_rt* routing_table, uint32_t target_ip){
	if (routing_table->dest.s_addr==target_ip) return 1;
	while (routing_table->next!=NULL){
		routing_table=routing_table->next;
		printf("my rt ip is: %d, target_ip is: %d\n",routing_table->dest.s_addr & routing_table->mask.s_addr,target_ip & routing_table->mask.s_addr);
		if (routing_table->dest.s_addr & routing_table->mask.s_addr & target_ip & routing_table->mask.s_addr) {
			printf("Routing table match!\n");
			return 1;
		}
	}
	return 0;
}

int sr_sendarpreply(struct sr_instance* sr, const char* iface, uint32_t ar_sip,unsigned char ar_sha[],uint32_t ar_tip,unsigned char ar_tha[]){
	uint8_t* arp_packet=generate_arp_packet(htons(arp_op_reply), ar_sha, ar_sip, ar_tha, ar_tip);
	uint8_t* ether_packet=generate_ethernet_frame(ar_tha,ar_sha,htons(ethertype_arp),arp_packet,sizeof(sr_arp_hdr_t));
	print_hdrs(ether_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
	int success= sr_send_packet(sr,ether_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t),iface);

	return success;
}
