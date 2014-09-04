#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <netinet/in.h>
#include "../ether_proto.h"
#include "../utils.h"
#include <linux/if_pppox.h>
#include "../pcap_stat.h"

static int ppp_disc_handler(struct pkt_buff *pb)
{
	struct pppoe_hdr *ppph;
	int ret = 0;
        uint32_t saddr, daddr, param1, param2;
	struct pcap_stat_node *stat;

        /* sanity check */
        if ((pb->tail - pb->data) < sizeof(struct pppoe_hdr))
                goto hdr_error;

	ppph = (struct pppoe_hdr *)pb_network_header(pb);

	pb->data += sizeof(*ppph);
	pb_set_network_header(pb, (pb->data - pb->head));
#if 0
	printf("\n[PPP] version:%d, type:%d, code:0x%02x, session_id:0x%04x, length:%d\n", 
		ppph->ver, ppph->type, ppph->code, ntohs(ppph->sid) ,ntohs(ppph->length));
#endif	
	return 0;

hdr_error:
	DBGMSG("ppp_disc header error!\n");
	return -1;
}

static struct ether_proto ppp_disc_proto = {
	.name 		= "PPP_DISC",
	.proto 		=  ETH_P_PPP_DISC,
	.handler 	= ppp_disc_handler,
};

void __init ppp_disc_init(void)
{
	ether_proto_register(&ppp_disc_proto);
}

