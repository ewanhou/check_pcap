#ifndef _PCAP_STAT_H
#define _PCAP_STAT_H
#include <stdint.h>
#include "list.h"

#define L4_PROTO_NONE 	0
#define L4_PROTO_ICMP 	1
#define L4_PROTO_TCP 	2
#define L4_PROTO_UDP	3

struct pcap_stat_node {
	uint32_t 	saddr;
	uint32_t 	daddr;
	uint32_t 	protocol;
	uint16_t	param1;		/* source port and icmp type */
	uint16_t	param2;		/* dest port and icmp code */
	uint64_t	count;

	struct hlist_node hlist;
};


extern void pcap_stat_tbl_init(void);
extern struct pcap_stat_node *pcap_stat_node_get(uint32_t saddr, uint32_t daddr,
			uint32_t protocol, uint16_t param1, uint16_t param2);

extern struct pcap_stat_node *pcap_stat_node_add(uint32_t saddr, uint32_t daddr,
			uint32_t protocol, uint16_t param1, uint16_t param2);

//extern void pcap_stat_show(void);
extern void pcap_stat_show(int flag, char *sip, char *dip);



#endif
