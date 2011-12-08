/*
 * packetinfo.h
 *
 *  Created on: 06.12.2011
 *      Author: jan
 */

#ifndef PACKETINFO_H_
#define PACKETINFO_H_

#include <libnetfilter_queue/libnetfilter_queue.h>

#define PACKETINFO_CMDLEN 256
#define PACKETINFO_ADDRLEN 64
#define PACKETINFO_DEVLEN IFNAMSIZ
#define PACKETINFO_PAYLOAD 0xFFFFU

enum transport_header_types {
	TCP,
	UDP,
	UNKNOWN_TRANSPORT_TYPE
};

enum network_header_types {
	IP,
	IP6,
	ICMP,
	ICMP6,
	UNKNOWN_NET_TYPE
};

struct packet_info {
	char  	process_cmd[PACKETINFO_CMDLEN];
	int		process_id;
	char  	remote_addr[PACKETINFO_ADDRLEN];	/* enough to hold an ipv6 address */
	int 	remote_port;

	char	interface[PACKETINFO_DEVLEN];

	enum transport_header_types transport_header_type;
	enum network_header_types network_header_type;

};

void pi_get(struct packet_info *pinfo, struct nlif_handle *nlif, struct nfq_data *tb);

#endif /* PACKETINFO_H_ */
