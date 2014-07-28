#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "../inet_proto.h"
#include "../utils.h"
#include "../pcap_stat.h"


static int icmp_handler(struct pkt_buff *pb)
{
	struct iphdr *iph;
	struct icmphdr *ih;
	uint32_t saddr, daddr, param1, param2;
	struct pcap_stat_node *stat;

	/* sanity check */
	/* TODO: Do we need to do the checksum check? */
	if ((pb->tail - pb->data) < sizeof(struct icmphdr))
		goto hdr_error;

	iph = (struct iphdr *)pb_network_header(pb);
	ih = (struct icmphdr *)pb_transport_header(pb);

	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);
	param1 = ntohs(ih->type);  //type
	param2 = ntohs(ih->code);  //code
	stat = pcap_stat_node_get(saddr, daddr, L4_PROTO_ICMP, param1, param2);
	if(!stat)
		stat = pcap_stat_node_add(saddr, daddr, L4_PROTO_ICMP, param1, param2);
	stat->count++;
	
	//DBGMSG("saddr:%s daddr:%s\n", ip2str(ntohl(iph->saddr)), ip2str(ntohl(iph->daddr)));


	return 0;

hdr_error:
	DBGMSG("icmp header error!\n");
	return -1;
}

static struct inet_proto icmp_proto = {
	.name 		= "ICMP",
	.proto 		= IPPROTO_ICMP,
	.handler 	= icmp_handler,
};

void __init icmp_init(void)
{
	inet_proto_register(&icmp_proto);
}

