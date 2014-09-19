#include <stdio.h>
#include <linux/ip.h>
#include "inet_proto.h"


LIST_HEAD(inet_proto_tbl);


void inet_proto_register(struct inet_proto *iprot)
{
	struct list_head *tmp, *walk;
	struct inet_proto *entry;

	list_for_each_safe(walk, tmp, &inet_proto_tbl) {
		entry = list_entry(walk, struct inet_proto, list);
		if (!strcmp(entry->name, iprot->name)) {
			printf("The inet proto '%s' has already registered.\n", iprot->name);
			return;
		}
	}

//	printf("Add inet proto `%s' handler\n", iprot->name);
	list_add_tail(&iprot->list, &inet_proto_tbl);
}

void inet_proto_handler(struct pkt_buff *pb)
{
	struct list_head *tmp, *walk;
	struct inet_proto *entry;
	struct iphdr *iph;
	unsigned short proto;

	iph = (struct iphdr *)pb_network_header(pb);
	proto = iph->protocol;

	list_for_each_safe(walk, tmp, &inet_proto_tbl) {
		entry = list_entry(walk, struct inet_proto, list);
		if (entry->proto == proto) {
			pb->data += (iph->ihl * 4);
			pb_set_transport_header(pb, (pb->data - pb->head));
			entry->handler(pb);
			break;
		}
	}
}

