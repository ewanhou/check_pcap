#include <stdlib.h>
#include "pcap_stat.h"
#include "jhash.h"
#include "utils.h"

#define PCAP_STAT_TABLE_SIZE		256

static struct hlist_head pcap_stat_tbl[PCAP_STAT_TABLE_SIZE];


static unsigned int pcap_stat_hash(uint32_t saddr, uint32_t daddr,
			uint16_t param1, uint16_t param2)
{
	unsigned int val;
	uint32_t a = saddr;
	uint32_t b = daddr;
	uint32_t c = ((uint32_t) param1 << 16) + (uint32_t) param2;
	val = jhash_3words(a, b, c, 0);
	return (val % PCAP_STAT_TABLE_SIZE);
}

void pcap_stat_tbl_init(void)
{
	int i;

	for (i = 0; i < PCAP_STAT_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&pcap_stat_tbl[i]);
}

struct pcap_stat_node *pcap_stat_node_get(uint32_t saddr, uint32_t daddr, 
			uint32_t protocol, uint16_t param1, uint16_t param2)
{
	struct pcap_stat_node *entry;
	struct hlist_node *walk, *tmp;
	unsigned int hashId = pcap_stat_hash(saddr, daddr, param1, param2);
	
	hlist_for_each_safe(walk, tmp, &pcap_stat_tbl[hashId]) {
		entry = hlist_entry(walk, struct pcap_stat_node, hlist);
		if ((entry->saddr == saddr) &&
		    (entry->daddr == daddr) &&
		    (entry->protocol == protocol) &&
		    (entry->param1 == param1) &&
		    (entry->param2 == param2))
		{
			return entry;
		}
	}

	return NULL;
}

struct pcap_stat_node *pcap_stat_node_add(uint32_t saddr, uint32_t daddr,
			uint32_t protocol, uint16_t param1, uint16_t param2)
{
	struct pcap_stat_node *entry;
	unsigned int hashId = pcap_stat_hash(saddr, daddr, param1, param2);

	entry = malloc(sizeof(struct pcap_stat_node));
	if (!entry)
		return NULL;

	entry->saddr = saddr;
	entry->daddr = daddr;
	entry->protocol = protocol;
	entry->param1 = param1;
	entry->param2 = param2;
	entry->count = 0;

	INIT_HLIST_NODE(&entry->hlist);
	hlist_add_head(&entry->hlist, &pcap_stat_tbl[hashId]);

	return entry;
}

void pcap_stat_show(int flag, char *srcip, char *dstip)
{
	struct pcap_stat_node *entry;
	struct hlist_node *walk, *tmp;
	int i;
	static char *proto_str[] = { "none", "icmp", "tcp", "udp" }; /* Need to sync with pcap_stat.h */

	if(flag == 1){
		//statistic Qurey
		printf("sip | dip | protocol | l4 info | counts\n");
		for (i = 0; i < PCAP_STAT_TABLE_SIZE; i++) {
			if (hlist_empty(&pcap_stat_tbl[i]))
				continue;
			hlist_for_each_safe(walk, tmp, &pcap_stat_tbl[i]) {
				entry = hlist_entry(walk, struct pcap_stat_node, hlist);
				printf("%s %s %s %d/%d %lu\n", ip2str(entry->saddr), ip2str(entry->daddr), proto_str[entry->protocol], entry->param1, entry->param2, entry->count);
			}
		}
	} else {
		//ip query
		//printf("\nsrcip = %s     dstip = %s\n", srcip, dstip);
        	for (i = 0; i < PCAP_STAT_TABLE_SIZE; i++) {
	        	if (hlist_empty(&pcap_stat_tbl[i]))
                                continue;
        		        hlist_for_each_safe(walk, tmp, &pcap_stat_tbl[i]) {
	                        entry = hlist_entry(walk, struct pcap_stat_node, hlist);
			        if(strcmp(srcip , ip2str(entry->saddr)) == 0 && strcmp(dstip, ip2str(entry->daddr)) == 0) {
			 		printf("protocol | l4 info | counts\n");
		                	//printf("%s %s %s %d/%d %lu\n", ip2str(entry->saddr), ip2str(entry->daddr), proto_str[entry->protocol], entry->param1, entry->param2, entry->count);
		                        printf("%s %d/%d %lu\n", proto_str[entry->protocol], entry->param1, entry->param2, entry->count);
				}
                        }
                }
	}

}

