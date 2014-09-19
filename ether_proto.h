#ifndef _ETHER_PROTO_H
#define _ETHER_PROTO_H
#include "libpcap-1.6.2/pcap/pcap.h"
#include "pkt_buff.h"
#include "list.h"

#define __init __attribute__((constructor))

struct ether_proto {
	char 			*name;
	unsigned short		proto; 	/* Please see /usr/include/linux/if_ether.h */
	int 			(*handler)(struct pkt_buff *pb);
	struct list_head 	list;
};

extern void ether_proto_register(struct ether_proto *eprot);
extern void ether_proto_handler(pcap_t *handle);


#endif
