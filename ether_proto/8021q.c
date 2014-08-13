#include <stdio.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "../ether_proto.h"
#include "../utils.h"

/* 802.1q vlan header */
struct vlan_hdr {
        __be16 pcp : 3;         /* priority code point (for 8021q) */
        __be16 cfi : 1;         /* canonical format indicator */
        __be16 vid : 12;        /* vlan identifier (0=no, fff=reserved) */
        __be16 type;         /* encapsulated type */
}__attribute ((packed));


static int vlan_handler(struct pkt_buff *pb)
{
	struct vlan_hdr *vlanh;
	struct iphdr *iph;
	int ret = 0;
	unsigned int len;
	unsigned short proto;

	if ((pb->tail - pb->data) < sizeof(struct vlan_hdr))
		goto hdr_error;	

	vlanh = (struct vlan_hdr *)pb_network_header(pb);	
	//printf("\n[802.1Q] priority:%x cfi:%x id:%x type:%x", vlanh->pcp, vlanh->cfi, vlanh->vid, vlanh->type);
	pb->data += sizeof(*vlanh);
	pb_set_network_header(pb, (pb->data - pb->head));
	
	proto = ntohs(vlanh->type);
	if (proto == 0x0800){   // Temporarily designated
		if ((pb->tail - pb->data) < sizeof(struct iphdr))
			goto hdr_error;
		iph = (struct iphdr *)pb_network_header(pb);
		if (iph->version == 4)
			inet_proto_handler(pb);
		else
			printf("Not in case!");
	}

	return 0;

hdr_error:
	DBGMSG("802.1q header error!\n");
	return -1;
}

static struct ether_proto vlan_proto = {
	.name 		= "8021Q",
	.proto 		=  ETH_P_8021Q,
	.handler 	= vlan_handler,
};

void __init vlan_init(void)
{
	ether_proto_register(&vlan_proto);
}

