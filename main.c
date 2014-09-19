#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "libpcap-1.6.2/pcap/pcap.h"
#include "pkt_buff.h"
#include "ether_proto.h"
#include "utils.h"

void usage(){
	printf("Usage: check_pcap <file> ip <src_ip> <des_ip>\n");
	printf("       check_pcap <file> statistic\n\n");

}

int isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int main(int argc, char **argv)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0, link_type, flag = 1;

	if (!(argc >= 3)) {
		usage();
		exit(1);
	}  else if(argc > 5) {
		usage();
                exit(1);
	}

	if(strcmp(argv[2], "statistic") == 0) {
		printf("\nDO STATISTIC\n");
		flag = 1;
	} else if(strcmp(argv[2], "ip") == 0) {
		printf("\nDO IP QUERY\n");
		int ret_1 = isValidIpAddress(argv[3]);
		int ret_2 = isValidIpAddress(argv[4]);
		if(ret_1 == 0 || ret_2 == 0) {
			printf("Error: Wrong ip format\n");
			exit(1);
		}
		flag = 0;
	} else {
		usage();
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

	//pcap_stat_show();
	pcap_stat_show(flag, argv[3], argv[4]);

	return 0;
}


