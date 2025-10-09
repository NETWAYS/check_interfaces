#include <limits.h>

#include <stdbool.h>

#ifdef HAVE_GETADDRINFO
#	include <netdb.h>
#	include <sys/socket.h>
#	include <sys/types.h>
#endif /* HAVE_GETADDRINFO */

#include <regex.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/*
 * defines
 * MAX_STRING = allocate memory for this length of output string
 */
#define MAX_STRING               65536
#define MAX_DESCR_LEN            255
#define UPTIME_TOLERANCE_IN_SECS 30
#define OFLO32                   4294967295ULL
#define OFLO64                   18446744073709551615ULL

/* default timeout is 30s */
#define DFLT_TIMEOUT 30000000UL

/* should a timeout return critical(2) or unknown(3)? */
#define EXITCODE_TIMEOUT 3

#define MEMCPY(a, b, c) memcpy(a, b, (sizeof(a) > c) ? c : sizeof(a))
#define TERMSTR(a, b)   a[(((sizeof(a) - 1) < b) ? (sizeof(a) - 1) : b)] = '\0'

/*
 * structs
 */

struct ifStruct {
	int ignore;
	int admin_down;
	int print_all_flag;
	int index;
	int status;
	int err_disable;
	char descr[MAX_DESCR_LEN];
	char alias[MAX_DESCR_LEN];
	char name[MAX_DESCR_LEN];
	unsigned long long inOctets;
	unsigned long long outOctets;
	unsigned long inDiscards;
	unsigned long outDiscards;
	unsigned long inErrors;
	unsigned long outErrors;
	unsigned long inUcast;
	unsigned long outUcast;
	unsigned long long speed;
	unsigned long long inbitps;
	unsigned long long outbitps;
};

struct OIDStruct {
	oid name[MAX_OID_LEN];
	size_t name_len;
};

/*
 * operating modes
 */
enum mode_enum {
	DEFAULT,
	CISCO,
	NONBULK,
	BINTEC
};

// Config
typedef struct configuration_struct {
	bool crit_on_down_flag;
	bool get_aliases_flag;
	bool match_aliases_flag;
	bool get_names_flag;
	bool print_all_flag;

	char *community;
	int bandwith;
	char *oldperfdatap;
	int err_tolerance;
	int coll_tolerance;
	char *hostname;
	char *port;
	char *user;
	char *auth_proto;
	char *auth_pass;
	char *priv_proto;
	char *priv_pass;
	unsigned int trimdescr;
	enum mode_enum mode; // hardware mode
	char *prefix;
	char *iface_regex;
	unsigned long global_timeout;
	char *exclude_list;
	unsigned long long speed;
	unsigned int lastcheck;
	unsigned int sleep_usecs;
	int session_retries;
	long pdu_max_repetitions;
	regex_t re;
	regex_t exclude_re;
} config_t;

/*
 * prototypes
 */
size_t sizeof_oid_if_bintec(void);
size_t sizeof_oid_if_get(void);
size_t sizeof_oid_if_bulkget(void);

void print64(struct counter64 *, const unsigned long *);
unsigned long long convertto64(struct counter64 *, const unsigned long *);
unsigned long long subtract64(unsigned long long, unsigned long long, unsigned int lastcheck, int uptime);
netsnmp_session *start_session(netsnmp_session *, char *, char *, enum mode_enum, unsigned long global_timeout, int session_retries);
netsnmp_session *start_session_v3(netsnmp_session *, char *, char *, char *, char *, char *, char *, unsigned long global_timeout,
								  int session_retries);
int usage(char *);
int parse_perfdata(char *, struct ifStruct *, char *, unsigned int *, int ifNumber, char *[]);
void set_value(struct ifStruct *, char *, char *, unsigned long long, int ifNumber, char *if_vars[]);
int parseoids(int, char *, struct OIDStruct *);
int create_request(netsnmp_session *, struct OIDStruct **, char **, int, netsnmp_pdu **, unsigned int sleep_usecs);
void create_pdu(int, char **, netsnmp_pdu **, struct OIDStruct **, int, long);
