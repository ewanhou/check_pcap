#include <stdio.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "../ether_proto.h"
#include "../utils.h"


static int ip_handler(struct pkt_buff *pb)
{
	struct iphdr *iph;
	int ret = 0;
	unsigned int len;

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

	//DBGMSG("saddr:%s daddr:%s\n", ip2str(ntohl(iph->saddr)), ip2str(ntohl(iph->daddr)));
	
	inet_proto_handler(pb);

	return 0;

hdr_error:
	DBGMSG("ip header error!\n");
	return -1;
}

static struct ether_proto ip_proto = {
	.name 		= "IP",
	.proto 		=  ETH_P_IP,
	.handler 	= ip_handler,
};

void __init ip_init(void)
{
	ether_proto_register(&ip_proto);
}

