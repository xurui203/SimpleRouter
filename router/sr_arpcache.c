#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_packet_builder.h"


#define MAX_ARP_SENT 5

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
	printf("Sweepreqs\n");
	struct sr_arpreq *request = sr->cache.requests;

	/*Next pointer saved before calling handle_arpreq in case current request is destroyed.*/
	while (request != NULL){
		printf("Handling request\n");
		struct sr_arpreq *next_request = request->next;
		sr_handle_arpreq(sr, request);
		request = next_request;
	}
}


void sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req){
	time_t now = time(NULL);
	/*where is req->sent initialized?*/
	if (1/*difftime(now, req->sent) > 1.0*/){

		/*If 5 or more ARP requests have already been sent, send ICMP host unreachable
		to source address of all packets waiting on this request.*/
		if (req->times_sent >= 5){
			/*send icmp of error type 3 and code 1*/
			sr_send_icmp_3(sr, req->packets, 1);
			sr_arpreq_destroy(&(sr->cache), req);
		}


		/*Resend ARP request every second, until 5 requests have been reached*/
		else{
			uint8_t *arp_request;
			uint8_t *ethernet_frame;
			unsigned int arp_ethernet_frame_size = sizeof(struct sr_arp_hdr)+sizeof(struct sr_ethernet_hdr);

			char out_interface_name[sr_IFACE_NAMELEN];
			struct sr_rt* rt = sr->routing_table;
			struct sr_rt* routing_match=sr_checkroutingtable(rt, req->ip);
			if (!routing_match){
				sr_send_icmp_3(sr, req->packets, 0);
				return;
			}
			memcpy(out_interface_name,routing_match->interface,sr_IFACE_NAMELEN);


			/*send arp request*/
			struct sr_if* out_interface = sr_get_interface(sr, out_interface_name);

			arp_request = generate_arp_packet(htons(arp_op_request), out_interface->addr, out_interface->ip, BROADCAST_MAC_ADDR, req->ip);
			ethernet_frame = generate_ethernet_frame((uint8_t*) BROADCAST_MAC_ADDR, out_interface->addr, htons(ethertype_arp), arp_request, sizeof(struct sr_arp_hdr));
			/*print_hdrs(ethernet_frame,arp_ethernet_frame_size);*/
			int send_success=sr_send_packet(sr, ethernet_frame, arp_ethernet_frame_size, out_interface_name);
			printf("Arp sent: %d\n",send_success);
			req->sent = now;
			req->times_sent ++;
			free(arp_request);
			free(ethernet_frame);
		}
	}

}


void sr_send_icmp_3(struct sr_instance *sr, struct sr_packet *req_pkt, int code ){
	/*for each packet waiting on the ARP request*/
	while (req_pkt != NULL){
		printf("Sending icmp3!\n");
		print_hdrs(req_pkt->buf,req_pkt->len);
		uint8_t* icmp_frame;
		uint8_t* ip_packet;
		uint8_t* ethernet_packet;

		int ip_data_length = sizeof(struct sr_icmp_t3_hdr);
		int ethernet_data_length = sizeof(struct sr_ip_hdr) + ip_data_length;
		unsigned int ethernet_packet_length = ethernet_data_length + sizeof(struct sr_ethernet_hdr);

		uint8_t* failed_packet = NULL;
		struct sr_ip_hdr* failed_ip_header = NULL;
		uint8_t* failed_ip_data = NULL;


		failed_packet = req_pkt->buf + sizeof(sr_ethernet_hdr_t);
		failed_ip_data = failed_packet + sizeof(sr_ip_hdr_t);
		failed_ip_header = (sr_ip_hdr_t*) failed_packet;

		icmp_frame = generate_icmp_3_frame(code, failed_packet);

		struct sr_if* source = sr_get_interface(sr, req_pkt->iface);
		ip_packet = generate_ip_packet(source->ip, failed_ip_header->ip_src, icmp_frame, ip_data_length);


		struct sr_arpentry *client_mac_addr = sr_arpcache_lookup(&sr->cache, failed_ip_header->ip_src);
		if (client_mac_addr){
			ethernet_packet = generate_ethernet_frame(client_mac_addr->mac, source->addr, ethertype_ip, ip_packet, ethernet_data_length);
			sr_send_packet(sr, ethernet_packet, ethernet_packet_length, req_pkt->iface);
		}else{
			uint8_t null_dest = 0;
			ethernet_packet = generate_ethernet_frame(&null_dest, source->addr, ethertype_ip, ip_packet, ethernet_data_length);
			sr_arpcache_queuereq(&sr->cache,failed_ip_header->ip_src, ethernet_packet, ethernet_packet_length, source->name);
		}
		free(icmp_frame);
		free(ip_packet);
		free(ethernet_packet);

		req_pkt = req_pkt->next;

		
	}
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

