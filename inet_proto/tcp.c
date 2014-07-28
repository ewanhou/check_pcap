#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "../inet_proto.h"
#include "../utils.h"
#include "../pcap_stat.h"


static int tcp_handler(struct pkt_buff *pb)
{

        struct iphdr *iph;
        struct tcphdr *tcph;
        uint32_t saddr, daddr, param1, param2;
        struct pcap_stat_node *stat;

        /* sanity check */
        /* TODO: Do we need to do the checksum check? */
        if ((pb->tail - pb->data) < sizeof(struct tcphdr))
                goto hdr_error;

        iph = (struct iphdr *)pb_network_header(pb);
        tcph = (struct tcphdr *)pb_transport_header(pb);

        saddr = ntohl(iph->saddr);
        daddr = ntohl(iph->daddr);
        param1 = ntohs(tcph->source);
        param2 = ntohs(tcph->dest);

	//printf("   TCP    source = %hu       dest = %hu\n", param1, param2);
        //printf("          saddr:%s           daddr:%s\n", ip2str(ntohl(iph->saddr)), ip2str(ntohl(iph->daddr)));


        stat = pcap_stat_node_get(saddr, daddr, L4_PROTO_TCP, param1, param2);
        if(!stat)
                stat = pcap_stat_node_add(saddr, daddr, L4_PROTO_TCP, param1, param2);
        stat->count++;

        //DBGMSG("saddr:%s daddr:%s\n", ip2str(ntohl(iph->saddr)), ip2str(ntohl(iph->daddr)));

        return 0;

hdr_error:
        DBGMSG("tcp header error!\n");
        return -1;
}

static struct inet_proto tcp_proto = {
        .name           = "TCP",
        .proto          = IPPROTO_TCP,
        .handler        = tcp_handler,
};

void __init tcp_init(void)
{
        inet_proto_register(&tcp_proto);
}

