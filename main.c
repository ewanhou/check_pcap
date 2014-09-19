#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "pkt_buff.h"
#include "ether_proto.h"
#include "utils.h"


int main(int argc, char **argv)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0, link_type;

	if (!(argc >= 3)) {
		printf("Usage: check_pcap <file>\n");
		exit(1);
	}  else if(argc > 5) {
                printf("Usage: check_pacp <file>\n");
                exit(1);
	}

	if(strcmp(argv[2], "statistic") == 0) {
		printf("DO STATISTIC\n");
	} else if(strcmp(argv[2], "ip") == 0) {
		printf("DO IP query\n");
	} else {
		printf("Usage: check_pacp <file>\n");
		exit(1);
	}

	handle = pcap_open_offline(argv[1], errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
		exit(2);
	}

	/* Check pcap global header */
	link_type = pcap_datalink(handle);
	switch(link_type) {
	case DLT_EN10MB:
		ether_proto_handler(handle);
		break;
	default:
		DBGMSG("Unknown datalink type (%d)\n", link_type);
		break;
	}

	pcap_close(handle); // close the pcap file

	pcap_stat_show();

	return 0;
}


