
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packetinfo.h"

#define LINEBUF_LEN 256

static inline  void hex2bin(char *bin, const char *src, int len) {
	int i;
	int val;
	for(i=0; i < len; i++) {
		sscanf(src, "%02X", &val);
		*bin++ = val & 0xFF;
		src += 2;
	}

}

static inline void reverse_address(char *s, int len) {
	int i;
	char c;
	for(i=0; i < len/2; i++) {
		c = s[i];
		s[i] = s[len-i-1];
		s[len-i-1] = c;
	}
}


static int compare_address(char *line, char *addr,
		enum network_header_types net) {

	char buf[64];
	int max_length;

	switch(net) {
	case IP:
		max_length = 4;
		break;
	case IP6:
		max_length = 16;
		break;
	default:
		break;
	}

	hex2bin(buf, line, max_length);
	reverse_address(buf, max_length);

	return !strncmp(buf, addr, max_length);
}

static int compare_port(char *line, int port) {
	int other = 0;
	sscanf(line, "%4x", &other);
	return (other == port);
}

static int parse_inode(char *line) {
	return strtol(line, 0, 10);
}

static int parse_tcp_table(struct packet_info *pinfo) {
	static char buf[LINEBUF_LEN];
	char *cur;
	int inode = -1;

	FILE *fp;

	fp = fopen("/proc/net/tcp", "r");

	// skip header line
	fgets(buf, LINEBUF_LEN, fp);


	while(fgets(buf, LINEBUF_LEN, fp)) {
		buf[strlen(buf)-1]='\0';
		cur = buf;
		/* skip to local address */
		while(*cur != ':') { cur++; }
		cur+=2;

		if(!compare_address(cur, pinfo->_raw.local_addr, IP))
			continue;
		cur +=9;
		if(!compare_port(cur, pinfo->local_port))
			continue;
		/* remote address */
		cur+=5;
		if(!compare_address(cur, pinfo->_raw.remote_addr, IP))
			continue;
		cur+=9;
		if(!compare_port(cur, pinfo->remote_port))
			continue;
		/* skip to inode */
		cur += 61;
		inode = parse_inode(cur);

		if(inode > 0)
			break;
	}
	fclose(fp);
	return inode;
}

int address2sockfd(struct packet_info *pinfo) {
	int inode = 0;

	if(pinfo->network_header_type == IP && pinfo->transport_header_type == TCP)
		inode = parse_tcp_table(pinfo);

	return inode;
}
