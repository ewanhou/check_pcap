#ifndef _LINUX_VLAN_H
#define _LINUX_VLAN_H

/* 802.1q vlan header */
struct vlan_hdr {
	__be16 pcp : 3;         /* priority code point (for 8021q) */
	__be16 cfi : 1;         /* canonical format indicator */
	__be16 vid : 12;        /* vlan identifier (0=no, fff=reserved) */
	__be16 type;         /* encapsulated type */
}__attribute ((packed));

#endif


