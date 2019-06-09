
#include <netinet/in.h>

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};
/* A few hardcoded protocols for 'all' and in case the user has no
   /etc/protocols */
struct pprot {
	char *name;
	u_int8_t num;
};

static const struct pprot chain_protos[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP },
	{ "esp", IPPROTO_ESP },
	{ "ah", IPPROTO_AH },
	{ "all", 0 },
};

/* Miscelaneous functions derived from ipchains */
struct in_addr *network_to_addr(const char *);
struct in_addr *host_to_addr(const char *, unsigned int *);
struct in_addr *parse_mask(char *);
struct in_addr *parse_hostnetwork(const char *, unsigned int *);
void parse_hostnetworkmask(const char *, struct in_addr **,
		      struct in_addr *, unsigned int *);

int string_to_number(const char *, int, int);

//static int service_to_port(const char *, unsigned short);
unsigned short int parse_protocol(const char *);
void inaddrcpy(struct in_addr *, struct in_addr *);
