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
	printf("IP Packet");
	print_hdrs(packet,len);
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t checksum=ip_header->ip_sum;
	ip_header->ip_sum=0;
	if (cksum(packet,len)!=checksum){
		printf("Error: IP checksum does not match packet");
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

	sr_arp_hdr_t *arp_header=(sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
	fprintf(stderr,"my ip is: %s\n",sr->sr_addr);
	/*if (ntohl(arp_header->ar_tip)==*/
}






