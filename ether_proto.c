#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include "ether_proto.h"


LIST_HEAD(ether_proto_tbl);

void ether_proto_register(struct ether_proto *eprot)
{
	struct list_head *tmp, *walk;
	struct ether_proto *entry;

	list_for_each_safe(walk, tmp, &ether_proto_tbl) {
		entry = list_entry(walk, struct ether_proto, list);
		if (!strcmp(entry->name, eprot->name)) {
			printf("The ether proto '%s' has already registered.\n", eprot->name);
			return;
		}
	}

	printf("Add ether proto `%s' handler\n", eprot->name);
	list_add_tail(&eprot->list, &ether_proto_tbl);
}

void ether_proto_handler(pcap_t *handle)
{
	const unsigned char *packet;
	struct pcap_pkthdr header;

	while (packet = pcap_next(handle, &header)) {
		struct pkt_buff *pb;
		struct ethhdr *eth;
		unsigned short proto;
		struct list_head *tmp, *walk;
		struct ether_proto *entry;

		if(header.caplen != header.len)
			printf("The packet is truncated!\n");

		pb = pkt_alloc(packet, &header);
		if(!pb)
			continue;
		//pkt_dump(pb);

		eth = (struct ethhdr *)pb_mac_header(pb);

		/* We don't handle 802.3/802.2/SNAP frames */
		if (eth->h_proto >= 1536 && ntohs(eth->h_proto) != 0x8100 && 
			ntohs(eth->h_proto) != 0x8863 && ntohs(eth->h_proto) != 0x8864) {

			pkt_free(pb);
			continue;
		}

		proto = ntohs(eth->h_proto);

		list_for_each_safe(walk, tmp, &ether_proto_tbl) {
			entry = list_entry(walk, struct ether_proto, list);
			if (entry->proto == proto) {
				pb->data += sizeof(*eth);
				pb_set_network_header(pb, (pb->data - pb->head));
				entry->handler(pb);
				break;
			}
		}
		
		pkt_free(pb);
	}
}

