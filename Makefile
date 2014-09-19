#####################################################################
#
# Makefile for check_pcap

ETHER_PROTO_SRCS = $(shell ls ether_proto/*.c 2>/dev/null)
ETHER_PROTO_OBJS = $(ETHER_PROTO_SRCS:%.c=%.o)

INET_PROTO_SRCS = $(shell ls inet_proto/*.c 2>/dev/null)
INET_PROTO_OBJS = $(INET_PROTO_SRCS:%.c=%.o)

CHECK_PCAP_SRCS = main.c pkt_buff.c pcap_stat.c utils.c ether_proto.c inet_proto.c
CHECK_PCAP_OBJS = $(CHECK_PCAP_SRCS:%.c=%.o) $(ETHER_PROTO_OBJS) $(INET_PROTO_OBJS)

LDFLAGS = -Llibpcap-1.6.2 \
	   -lpcap

SUBDIRS = ether_proto inet_proto


all: 
	@for i in $(SUBDIRS); do \
		if [ -d $$i ]; then \
		$(MAKE) -C $$i $@ || exit $$? ; \
		fi; \
		done
	$(MAKE) check_pcap


check_pcap: $(CHECK_PCAP_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f check_pcap *.o
	@for i in $(SUBDIRS); do \
		if [ -d $$i ]; then \
		$(MAKE) -C $$i $@ || exit $$? ; \
		fi; \
		done


