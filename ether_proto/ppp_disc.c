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
	unsigned int len;
        uint32_t saddr, daddr, param1, param2;
	struct pcap_stat_node *stat;

	ppph = (struct pppoe_hdr *)pb_network_header(pb);
#if 0
	/* sanity check */
	if ((pb->tail - pb->data) < sizeof(struct iphdr))
		goto hdr_error;

	iph = (struct iphdr *)pb_network_header(pb);

	if (iph->ihl < 5 || iph->version != 4)
		goto hdr_error;

	if ((pb->tail - pb->data) < (iph->ihl * 4))
		goto hdr_error;

	len = ntohs(iph->tot_len);
	if (len < (iph->ihl * 4))
		goto hdr_error;
#endif
	len = ntohs(ppph->length);
//	printf("\n\nversion:%x type:%x code:%x length:%d\n\n", ppph->ver, ppph->type, ppph->code, len);

        param1 = ppph->type;  //type
        param2 = ppph->code;  //code
        stat = pcap_stat_node_get(saddr, daddr, L4_PROTO_NONE, param1, param2);

        if(!stat)
                stat = pcap_stat_node_add(saddr, daddr, L4_PROTO_NONE, param1, param2);
        stat->count++;

	
	//inet_proto_handler(pb);

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

