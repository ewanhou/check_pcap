#ifndef _PKT_BUFF_H
#define _PKT_BUFF_H

#include <stdint.h>
#include "libpcap-1.6.2/pcap/pcap.h"


struct pkt_buff {
	unsigned int		len;
	uint16_t		transport_header;
	uint16_t		network_header;
	uint16_t		mac_header;
	unsigned char		*head,
				*data,
				*tail;
};



static inline unsigned char *pb_transport_header(const struct pkt_buff *pb)
{
	return pb->head + pb->transport_header;
}

static inline int pb_transport_header_was_set(const struct pkt_buff *pb)
{
	return (pb->transport_header != 0);
}

static inline void pb_reset_transport_header(struct pkt_buff *pb)
{
	pb->transport_header = 0;
}

static inline void pb_set_transport_header(struct pkt_buff *pb, const int offset)
{
	pb_reset_transport_header(pb);
	pb->transport_header += offset;
}

static inline unsigned char *pb_network_header(const struct pkt_buff *pb)
{
	return pb->head + pb->network_header;
}

static inline int pb_network_header_was_set(const struct pkt_buff *pb)
{
	return (pb->network_header != 0);
}

static inline void pb_reset_network_header(struct pkt_buff *pb)
{
	pb->network_header = 0;
}

static inline void pb_set_network_header(struct pkt_buff *pb, const int offset)
{
	pb_reset_network_header(pb);
	pb->network_header += offset;
}

static inline unsigned char *pb_mac_header(const struct pkt_buff *pb)
{
	return pb->head + pb->mac_header;
}

extern void pkt_dump(struct pkt_buff *pb);
extern struct pkt_buff *pkt_alloc(const unsigned char *packet, struct pcap_pkthdr *header);
extern void pkt_free(struct pkt_buff *pb);

#endif
