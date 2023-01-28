

#include <limits.h>

#ifdef HAVE_GETADDRINFO
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif /* HAVE_GETADDRINFO */

#include <regex.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/*
 * defines
 * MAX_STRING = allocate memory for this length of output string
 */
#define MAX_STRING 65536
#define MAX_DESCR_LEN 255
#define UPTIME_TOLERANCE_IN_SECS 30
#define OFLO32 4294967295ULL
#define OFLO64 18446744073709551615ULL

/* default timeout is 30s */
#define DFLT_TIMEOUT 30000000UL

/* should a timeout return critical(2) or unknown(3)? */
#define EXITCODE_TIMEOUT 3

#define MEMCPY(a, b, c) memcpy(a, b, (sizeof(a)>c)?c:sizeof(a))
#define TERMSTR(a, b) a[(((sizeof(a)-1)<b)?(sizeof(a)-1):b)] = '\0'

#ifndef U64
#define U64
typedef unsigned long long u64;
#endif


/*
 * structs
 */

struct ifStruct {
    int     ignore;
    int     admin_down;
    int     print_all_flag;
    int     index;
    int     status;
    int     err_disable;
    char    descr[MAX_DESCR_LEN];
    char    alias[MAX_DESCR_LEN];
    char    name[MAX_DESCR_LEN];
    u64     inOctets;
    u64     outOctets;
    unsigned long   inDiscards;
    unsigned long   outDiscards;
    unsigned long   inErrors;
    unsigned long   outErrors;
    unsigned long   inUcast;
    unsigned long   outUcast;
    u64     speed;
    u64     inbitps;
    u64     outbitps;
};

struct OIDStruct {
    oid             name[MAX_OID_LEN];
    size_t          name_len;
};



/*
 * text strings to output in the perfdata
 */

static char *if_vars_default[] = {
            "inOctets",
            "outOctets",
            "inDiscards",
            "outDiscards",
            "inErrors",
            "outErrors",
            "inUcast",
            "outUcast",
            "speed",
            "inBitps",
            "outBitps" };

static char *if_vars_cisco[] = {
            "inOctets",
            "outOctets",
            "inDiscards",
            "outDiscards",
            "inCRCs",
            "outCollisions",
            "inUcast",
            "outUcast",
            "speed",
            "inBitps",
            "outBitps" };




/*
 * OIDs, hardcoded to remove the dependency on MIBs
 */
static char    *oid_if_bulkget[] = {".1.3.6.1.2.1.1.3", ".1.3.6.1.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2", 0}; /* "uptime", "ifNumber", "ifDescr" */
static char    *oid_if_get[] = {".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.1.0", ".1.3.6.1.2.1.2.2.1.2.1", 0}; /* "uptime", "ifNumber", "ifDescr" */
static char    *oid_if_bintec[] = {".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.1.0", ".1.3.6.1.2.1.2.2.1.2.0", 0}; /* "uptime", "ifNumber", "ifDescr" */
static char    *oid_alias_bulkget[] = {".1.3.6.1.2.1.31.1.1.1.18", 0}; /* "alias" */
static char    *oid_alias_get[] = {".1.3.6.1.2.1.31.1.1.1.18.1", 0}; /* "alias" */
static char    *oid_alias_bintec[] = {".1.3.6.1.2.1.31.1.1.1.18.0", 0}; /* "alias" */
static char    *oid_names_bulkget[] = {".1.3.6.1.2.1.31.1.1.1.1", 0}; /* "name" */
static char    *oid_names_get[] = {".1.3.6.1.2.1.31.1.1.1.1.1", 0}; /* "name" */
static char    *oid_names_bintec[] = {".1.3.6.1.2.1.31.1.1.1.1.0", 0}; /* "name - NOT TESTED!" */

static char    *oid_vals_default[] = {
    ".1.3.6.1.2.1.2.2.1.7",    /* ifAdminStatus */
    ".1.3.6.1.2.1.2.2.1.8",    /* ifOperStatus */
    ".1.3.6.1.2.1.2.2.1.10",   /* ifInOctets */
    ".1.3.6.1.2.1.2.2.1.13",   /* ifInDiscards */
    ".1.3.6.1.2.1.2.2.1.14",   /* ifInErrors */
    ".1.3.6.1.2.1.2.2.1.16",   /* ifOutOctets */
    ".1.3.6.1.2.1.2.2.1.19",   /* ifOutDiscards */
    ".1.3.6.1.2.1.2.2.1.20",   /* ifOutErrors */
    0
};

static char    *oid_vals_cisco[] = {
    ".1.3.6.1.2.1.2.2.1.7",    /* ifAdminStatus */
    ".1.3.6.1.2.1.2.2.1.8",    /* ifOperStatus */
    ".1.3.6.1.2.1.2.2.1.10",   /* ifInOctets */
    ".1.3.6.1.2.1.2.2.1.13",   /* ifInDiscards */
    ".1.3.6.1.4.1.9.2.2.1.1.12",   /* locIfInCRC */
    ".1.3.6.1.2.1.2.2.1.16",   /* ifOutOctets */
    ".1.3.6.1.2.1.2.2.1.19",   /* ifOutDiscards */
    ".1.3.6.1.4.1.9.2.2.1.1.25",   /* locIfCollisions */
    0
};

static char *oid_extended[] = {
    ".1.3.6.1.2.1.31.1.1.1.6", /* ifHCInOctets */
    ".1.3.6.1.2.1.31.1.1.1.10",/* ifHCOutOctets */
    ".1.3.6.1.2.1.2.2.1.11",   /* ifInUcastPkts */
    ".1.3.6.1.2.1.2.2.1.17",   /* ifOutUcastPkts */
    ".1.3.6.1.2.1.2.2.1.5",    /* ifSpeed */
    ".1.3.6.1.2.1.31.1.1.1.15",/* ifHighSpeed */
    ".1.3.6.1.2.1.31.1.1.1.18",/* alias */
    ".1.3.6.1.2.1.31.1.1.1.1", /* name */
    0
};

static char *oid_extended_cisco[] = {
    ".1.3.6.1.4.1.9.5.1.4.1.1.23", /* portAdditionalOperStatus */
    0
};




static char default_community[] = "public";




/*
 * operating modes
 */


const char *modes[] = { "default", "cisco", "nonbulk", "bintec", NULL };
enum mode_enum { DEFAULT, CISCO, NONBULK, BINTEC };

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
    int     err_tolerance;
    int     coll_tolerance;
    char *hostname;
    char *user;
    char *auth_proto;
    char *auth_pass;
    char *priv_proto;
    char *priv_pass;
    int trimdescr;
    enum mode_enum mode; // hardware mode
    char *prefix;
    char *list;
    unsigned long global_timeout;
    char *exclude_list;
    u64     speed;
    unsigned int lastcheck;
    unsigned int sleep_usecs;
    int session_retries;
    long pdu_max_repetitions;
    regex_t re;
    regex_t exclude_re;
} config;


/*
 * prototypes
 */

void print64(struct counter64*, unsigned long*);
u64 convertto64(struct counter64 *, unsigned long *);
u64 subtract64(u64, u64, unsigned int lastcheck);
netsnmp_session *start_session(netsnmp_session *, char *, char *, enum mode_enum, unsigned long global_timeout, int session_retries);
netsnmp_session *start_session_v3(netsnmp_session *, char *, char *, char *, char *, char *, char *, unsigned long global_timeout, int session_retries);
int usage(char *);
int parse_perfdata(char *, struct ifStruct *, char *, unsigned int *, enum mode_enum);
void set_value(struct ifStruct *, char *, char *, u64, char *, enum mode_enum);
int parseoids(int, char *, struct OIDStruct *);
int create_request(netsnmp_session *, struct OIDStruct **, char **, int, netsnmp_pdu **, unsigned int sleep_usecs);
