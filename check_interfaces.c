// This one is needed on FreeBSD and it has to be before the others or at least some of them
#include <getopt.h>

#include "snmp_bulkget.h"
#include "utils.h"
#include <net-snmp/net-snmp-config.h>
#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * text strings to output in the perfdata
 */

static char *if_vars_default[] = {"inOctets", "outOctets", "inDiscards", "outDiscards", "inErrors", "outErrors",
						   "inUcast",  "outUcast",  "speed",      "inBitps",     "outBitps"};

static char *if_vars_cisco[] = {"inOctets", "outOctets", "inDiscards", "outDiscards", "inCRCs",  "outCollisions",
						 "inUcast",  "outUcast",  "speed",      "inBitps",     "outBitps"};

/*
 * OIDs, hardcoded to remove the dependency on MIBs
 */
static char *oid_if_bulkget[] = {".1.3.6.1.2.1.1.3", ".1.3.6.1.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2", 0}; /* "uptime", "ifNumber", "ifDescr" */

static char *oid_if_get[] = {".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.1.0", ".1.3.6.1.2.1.2.2.1.2.1", 0}; /* "uptime", "ifNumber", "ifDescr" */

static char *oid_if_bintec[] = {".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.1.0", ".1.3.6.1.2.1.2.2.1.2.0", 0}; /* "uptime", "ifNumber", "ifDescr" */

static char *oid_extended[] = {".1.3.6.1.2.1.31.1.1.1.6",  /* ifHCInOctets */
						".1.3.6.1.2.1.31.1.1.1.10", /* ifHCOutOctets */
						".1.3.6.1.2.1.2.2.1.11",    /* ifInUcastPkts */
						".1.3.6.1.2.1.2.2.1.17",    /* ifOutUcastPkts */
						".1.3.6.1.2.1.2.2.1.5",     /* ifSpeed */
						".1.3.6.1.2.1.31.1.1.1.15", /* ifHighSpeed */
						".1.3.6.1.2.1.31.1.1.1.18", /* alias */
						".1.3.6.1.2.1.31.1.1.1.1",  /* name */
						0};

static char *oid_alias_bulkget[] = {".1.3.6.1.2.1.31.1.1.1.18", 0};  /* "alias" */
static char *oid_alias_get[] = {".1.3.6.1.2.1.31.1.1.1.18.1", 0};    /* "alias" */
static char *oid_alias_bintec[] = {".1.3.6.1.2.1.31.1.1.1.18.0", 0}; /* "alias" */
static char *oid_names_bulkget[] = {".1.3.6.1.2.1.31.1.1.1.1", 0};   /* "name" */
static char *oid_names_get[] = {".1.3.6.1.2.1.31.1.1.1.1.1", 0};     /* "name" */
static char *oid_names_bintec[] = {".1.3.6.1.2.1.31.1.1.1.1.0", 0};  /* "name - NOT TESTED!" */
static char *oid_extended_cisco[] = {".1.3.6.1.4.1.9.5.1.4.1.1.23",  /* portAdditionalOperStatus */
							  0};

static char *oid_vals_default[] = {".1.3.6.1.2.1.2.2.1.7",  /* ifAdminStatus */
							".1.3.6.1.2.1.2.2.1.8",  /* ifOperStatus */
							".1.3.6.1.2.1.2.2.1.10", /* ifInOctets */
							".1.3.6.1.2.1.2.2.1.13", /* ifInDiscards */
							".1.3.6.1.2.1.2.2.1.14", /* ifInErrors */
							".1.3.6.1.2.1.2.2.1.16", /* ifOutOctets */
							".1.3.6.1.2.1.2.2.1.19", /* ifOutDiscards */
							".1.3.6.1.2.1.2.2.1.20", /* ifOutErrors */
							0};

static char *oid_vals_cisco[] = {".1.3.6.1.2.1.2.2.1.7",      /* ifAdminStatus */
						  ".1.3.6.1.2.1.2.2.1.8",      /* ifOperStatus */
						  ".1.3.6.1.2.1.2.2.1.10",     /* ifInOctets */
						  ".1.3.6.1.2.1.2.2.1.13",     /* ifInDiscards */
						  ".1.3.6.1.4.1.9.2.2.1.1.12", /* locIfInCRC */
						  ".1.3.6.1.2.1.2.2.1.16",     /* ifOutOctets */
						  ".1.3.6.1.2.1.2.2.1.19",     /* ifOutDiscards */
						  ".1.3.6.1.4.1.9.2.2.1.1.25", /* locIfCollisions */
						  0};

#define DEFAULT_COMMUNITY "public"

/*
 * operating modes
 */
static const char *modes[] = {"default", "cisco", "nonbulk", "bintec", NULL};

#ifdef DEBUG
static char *implode_result;
#endif

enum returncode {
	OK = 0,
	WARNING = 1,
	CRITICAL = 2,
	UNKNOWN = 3
};

typedef enum returncode returncode_t;

// Forward declarations
static void parse_and_check_commandline(int argc, char **argv, struct configuration_struct *config);
static bool fetch_interface_aliases(struct configuration_struct * /*config*/, char ** /*oid_aliasp*/, netsnmp_session *snmp_session,
							 netsnmp_session *session, struct ifStruct *interfaces, int ifNumber);
static bool fetch_interface_names(struct configuration_struct * /*config*/, char **oid_namesp, netsnmp_session *snmp_session,
						   netsnmp_session *session, struct ifStruct *interfaces, int ifNumber);
static returncode_t print_output(struct configuration_struct *config, struct ifStruct *oldperfdata, long double starttime,
						  struct ifStruct *interfaces, String *out, char **if_vars, unsigned int number_of_matched_interfaces,
						  struct timeval *time_value, int uptime, int ifNumber);
static void print_version(void);

int main(int argc, char *argv[]) {
	config_t config = {
		.crit_on_down_flag = true,
		.get_aliases_flag = false,
		.match_aliases_flag = false,
		.get_names_flag = false,
		.print_all_flag = false,
		.community = DEFAULT_COMMUNITY,
		.bandwith = 0,
		.oldperfdatap = 0,
		.err_tolerance = 50,
		.coll_tolerance = -1,
		.hostname = 0,
		.port = "161",
		.user = 0,
		.auth_proto = 0,
		.auth_pass = 0,
		.priv_proto = 0,
		.priv_pass = 0,
		.trimdescr = 0,
		.prefix = 0,
		.iface_regex = 0,
		.global_timeout = DFLT_TIMEOUT,
		.exclude_list = 0,
		.speed = 0,
		.lastcheck = 0,
		.sleep_usecs = 0,
		.session_retries = 2,
		.pdu_max_repetitions = 4096L,
		.mode = DEFAULT,
	};

	parse_and_check_commandline(argc, argv, &config);

	struct timeval time_value;
	struct timezone time_zone;
	gettimeofday(&time_value, &time_zone);
	long double starttime = (long double)time_value.tv_sec + (((long double)time_value.tv_usec) / 1000000);

	// +1 for the `:` between hostname and port
	size_t peername_max_len = strlen(config.hostname) + strlen(config.port) + 1;
	char *peername = calloc(1, peername_max_len + 1);
	if (peername == NULL) {
		printf("Failed to allocate memory at %d in %s\n", __LINE__, __FUNCTION__);
		exit(3);
	}

	strlcpy(peername, config.hostname, peername_max_len + 1);
	strlcat(peername, ":", peername_max_len + 1);
	strlcat(peername, config.port, peername_max_len + 1);

#ifdef DEBUG
	benchmark_start("Start SNMP session");
#endif
	netsnmp_session session;
	netsnmp_session *snmp_session;
	if (config.user) {
		/* use snmpv3 */
		snmp_session = start_session_v3(&session, config.user, config.auth_proto, config.auth_pass, config.priv_proto, config.priv_pass,
										peername, config.global_timeout, config.session_retries);
	} else {
		snmp_session = start_session(&session, config.community, peername, config.mode, config.global_timeout, config.session_retries);
	}
#ifdef DEBUG
	benchmark_end();
#endif

	size_t size = 0;
	char **oid_aliasp;
	char **oid_namesp;
	char **oid_ifp = oid_if_bulkget;
	if (config.mode == NONBULK) {
		oid_ifp = oid_if_get;
		size = (sizeof(oid_if_get) / sizeof(char *)) - 1;
		oid_aliasp = oid_alias_get;
		oid_namesp = oid_names_get;
	} else if (config.mode == BINTEC) {
		oid_ifp = oid_if_bintec;
		size = (sizeof(oid_if_bintec) / sizeof(char *)) - 1;
		oid_aliasp = oid_alias_bintec;
		oid_namesp = oid_names_bintec;
	} else {
		oid_ifp = oid_if_bulkget;
		size = (sizeof(oid_if_bulkget) / sizeof(char *)) - 1;
		oid_aliasp = oid_alias_bulkget;
		oid_namesp = oid_names_bulkget;
	}

	/* allocate the space for the interface OIDs */
	struct OIDStruct *OIDp = (struct OIDStruct *)calloc(size, sizeof(struct OIDStruct));

	char **oid_vals = oid_vals_default;
	char **if_vars = if_vars_default;
	if (config.mode == CISCO) {
		if_vars = if_vars_cisco;
		oid_vals = oid_vals_cisco;
	}

	/* get the number of interfaces, and their index numbers
	 *
	 * We will attempt to get all the interfaces in a single packet
	 * - which should manage about 64 interfaces.
	 * If the end interface has not been reached, we fetch more packets - this
	 * is necessary to work around buggy switches that lie about the ifNumber
	 */

	netsnmp_pdu *response;
	netsnmp_pdu *pdu;
	int count = 0; /* used for: the number of interfaces we receive, the number
					  of regex matches */
	/* uptime counter */
	unsigned int uptime = 0;
	int ifNumber = 0;
	struct OIDStruct lastOid;
	struct ifStruct *interfaces = NULL;  /* current interface data */
	struct ifStruct *oldperfdata = NULL; /* previous check interface data */
	char outstr[MAX_STRING];
	memset(outstr, 0, sizeof(outstr));
	String out = {
		.max = MAX_STRING,
		.len = 0,
		.text = outstr,
	};

	for (bool lastifflag = false; lastifflag != true;) {
		/* build our request depending on the mode */
		if (count == 0) {
			create_pdu(config.mode, oid_ifp, &pdu, &OIDp, 2, config.pdu_max_repetitions);
		} else {
			/* we have not received all interfaces in the preceding packet, so
			 * fetch the next lot */

			if (config.mode == BINTEC || config.mode == NONBULK) {
				pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
			} else {
				pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
				pdu->non_repeaters = 0;
				pdu->max_repetitions = config.pdu_max_repetitions;
			}
			snmp_add_null_var(pdu, lastOid.name, lastOid.name_len);
		}

#ifdef DEBUG
		implode_result = implode(", ", oid_ifp + count);
		benchmark_start("Send SNMP request for OIDs: %s", implode_result);
#endif
		/* send the request */
		int status = snmp_synch_response(snmp_session, pdu, &response);
#ifdef DEBUG
		benchmark_end();
		free(implode_result);
#endif
		if (config.sleep_usecs) {
			usleep(config.sleep_usecs);
		}

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
			netsnmp_variable_list *vars = response->variables;

			if (count == 0) {
				/* assuming that the uptime and ifNumber come first */
				/*  on some devices the ifNumber is not available... */

				while (!ifNumber) {
					if (!(memcmp(OIDp[0].name, vars->name, OIDp[0].name_len * sizeof(oid)))) {
						/* uptime */
						if (vars->type == ASN_TIMETICKS) {
							/* uptime is in 10ms units -> convert to seconds */
							uptime = *(vars->val.integer) / 100;
						}
					} else if (!memcmp(OIDp[1].name, vars->name, OIDp[1].name_len * sizeof(oid))) {
						/* we received a valid IfNumber */
						ifNumber = *(vars->val.integer);
						if (ifNumber == 0) {
							/* there are no interfaces! Stop here */
							printf("No interfaces found");
							exit(0);
						}
					} else {
						addstr(&out, "(no IfNumber parameter, assuming 32 interfaces) ");
						ifNumber = 32;
					}

					vars = vars->next_variable;
				}

				// get the real list length we need
				int real_count = 0;
				for (netsnmp_variable_list *runner = response->variables; runner; runner = runner->next_variable) {
					if (vars->type == ASN_OCTET_STR) {
						real_count++;
					}
				}

				if (real_count > ifNumber) {
					ifNumber = real_count;
				}

				interfaces = (struct ifStruct *)calloc((size_t)ifNumber, sizeof(struct ifStruct));
				oldperfdata = (struct ifStruct *)calloc((size_t)ifNumber, sizeof(struct ifStruct));

#ifdef DEBUG
				fprintf(stderr, "got %d interfaces\n", ifNumber);
#endif
			} else {
				/* subsequent replies have no ifNumber */
			}

			for (; vars; vars = vars->next_variable) {
				/*
				 * if the next OID is shorter
				 * or if the next OID doesn't begin with our base OID
				 * then we have reached the end of the table :-)
				 * print_variable(vars->name, vars->name_length, vars);
				 */

				/* save the OID in case we need additional packets */
				memcpy(lastOid.name, vars->name, (vars->name_length * sizeof(oid)));
				lastOid.name_len = vars->name_length;

				if ((vars->name_length < OIDp[2].name_len) || (memcmp(OIDp[2].name, vars->name, (vars->name_length - 1) * sizeof(oid)))) {
#ifdef DEBUG
					fprintf(stderr, "reached end of interfaces\n");
#endif
					lastifflag = true;
					break;
				}

				/* now we fill our interfaces array with the index number and
				 * the description that we have received
				 */
				if (vars->type == ASN_OCTET_STR) {
					if (config.trimdescr && config.trimdescr < vars->val_len) {
						interfaces[count].index = vars->name[(vars->name_length - 1)];

						MEMCPY(interfaces[count].descr, (vars->val.string) + config.trimdescr, vars->val_len - config.trimdescr);

						TERMSTR(interfaces[count].descr, vars->val_len - config.trimdescr);
					} else {
						interfaces[count].index = vars->name[(vars->name_length - 1)];

						MEMCPY(interfaces[count].descr, vars->val.string, vars->val_len);
						TERMSTR(interfaces[count].descr, vars->val_len);
					}
					count++;
				}
			}

			if (count < ifNumber) {
				if (lastifflag) {
#ifdef DEBUG
					fprintf(stderr, "Device says it has %d but really has %d interfaces\n", ifNumber, count);
#endif
					ifNumber = count;
				} else {
#ifdef DEBUG
					fprintf(stderr, "Sending another packet\n");
#endif
				}
			} else {
				lastifflag = true;
				if (count > ifNumber) {
#ifdef DEBUG
					fprintf(stderr, "Device says it has %d but really has %d interfaces\n", ifNumber, count);
#endif
					ifNumber = count;
				}
#ifdef DEBUG
				fprintf(stderr, "%d interfaces found\n", ifNumber);
#endif
			}

		} else {
			/*
			 * FAILURE: print what went wrong!
			 */

			if (status == STAT_SUCCESS) {
				printf("Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
			} else if (status == STAT_TIMEOUT) {
				printf("Timeout while reading interface descriptions from %s\n", session.peername);
				exit(EXITCODE_TIMEOUT);
			} else if (status == STAT_ERROR && snmp_session->s_snmp_errno == SNMPERR_TIMEOUT) {
				printf("Timeout\n");
				exit(EXITCODE_TIMEOUT);
			} else {
				snmp_sess_perror("snmp_bulkget", snmp_session);
			}
			exit(2);
		}
		/*
		 * Clean up:
		 *   free the response.
		 */
		if (response) {
			snmp_free_pdu(response);
			response = 0;
		}
	}

	if (OIDp) {
		free(OIDp);
		OIDp = 0;
	}

	/* we should have all interface descriptions in our array */

	/* If we want to match the regex with the aliases, we have to get them now.
	 * this allows us later to only request the interface counters of the
	 * desired interfaces.
	 */

	if (config.match_aliases_flag && config.iface_regex) {
		fetch_interface_aliases(&config, oid_aliasp, snmp_session, &session, interfaces, ifNumber);
	}

	/* If the get_names_flag is set, we also have to get the interface names so
	 * we can match the regex with them */

	/* TODO: This is just a slightly changed copy from above. I think it could
	 * be solved better (i.e. by putting it into a function) but it works this
	 * way
	 * :-) */
	if (config.get_names_flag && config.iface_regex) {
		fetch_interface_names(&config, oid_namesp, snmp_session, &session, interfaces, ifNumber);
	}

	if (config.iface_regex) {
		/*
		 * a regex was given so we will go through our array
		 * and try and match it with what we received
		 *
		 * count is the number of matches
		 */

		count = 0;
		for (int i = 0; i < ifNumber; i++) {
			/* When --if-name is set ignore descr in favor of name, else use old
			 * behaviour */
			int status = 0;
			if (config.get_names_flag) {
				status = !regexec(&config.re, interfaces[i].name, (size_t)0, NULL, 0) ||
						 (config.match_aliases_flag && !(regexec(&config.re, interfaces[i].alias, (size_t)0, NULL, 0)));
			} else {
				status = !regexec(&config.re, interfaces[i].descr, (size_t)0, NULL, 0) ||
						 (config.match_aliases_flag && !(regexec(&config.re, interfaces[i].alias, (size_t)0, NULL, 0)));
			}

			int status2 = 0;
			if (status && config.exclude_list) {
				if (config.get_names_flag) {
					status2 = !regexec(&config.exclude_re, interfaces[i].name, (size_t)0, NULL, 0) ||
							  (config.match_aliases_flag && !(regexec(&config.re, interfaces[i].alias, (size_t)0, NULL, 0)));
				} else {
					status2 = !regexec(&config.exclude_re, interfaces[i].descr, (size_t)0, NULL, 0) ||
							  (config.match_aliases_flag && !(regexec(&config.exclude_re, interfaces[i].alias, (size_t)0, NULL, 0)));
				}
			}
			if (status && !status2) {
				count++;
#ifdef DEBUG
				fprintf(stderr, "Interface %d (%s) matched\n", interfaces[i].index, interfaces[i].descr);
#endif
			} else {
				interfaces[i].ignore = 1;
			}
		}
		regfree(&config.re);

		if (config.exclude_list) {
			regfree(&config.exclude_re);
		}

		if (count) {
#ifdef DEBUG
			fprintf(stderr, "- %d interface%s found\n", count, (count == 1) ? "" : "s");
#endif
		} else {
			printf("- no interfaces matched regex");
			exit(0);
		}
	}

	/* now retrieve the interface values in 2 GET requests
	 * N.B. if the interfaces are continuous we could try
	 * a bulk get instead
	 */
	int ignore_count = 0;
	for (int j = 0, k = 0; j < ifNumber; j++) {
		/* add the interface to the oldperfdata list */
		strcpy_nospaces(oldperfdata[j].descr, interfaces[j].descr);

		if (!interfaces[j].ignore) {
			/* fetch the standard values first */
			if (create_request(snmp_session, &OIDp, oid_vals, interfaces[j].index, &response, config.sleep_usecs)) {
				for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable) {
					k = -1;
					/* compare the received value to the requested value */
					for (int i = 0; oid_vals[i]; i++) {
						if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len * sizeof(oid))) {
							k = i;
							break;
						}
					}

					switch (k) /* the offset into oid_vals */
					{
					case 0: /* ifAdminStatus */
						if (vars->type == ASN_INTEGER && *(vars->val.integer) == 2) {
							/* ignore interfaces that are administratively down
							 */
							interfaces[j].admin_down = 1;
							ignore_count++;
						}
						break;
					case 1: /*ifOperStatus */
						if (vars->type == ASN_INTEGER) {
							/* 1 is up(OK), 3 is testing (assume OK), 5 is
							 * dormant(assume OK)
							 */
							interfaces[j].status =
								(*(vars->val.integer) == 1 || *(vars->val.integer) == 5 || *(vars->val.integer) == 3) ? 1 : 0;
						}
						break;
					case 2: /* ifInOctets */
						if (vars->type == ASN_COUNTER) {
							interfaces[j].inOctets = *(vars->val.integer);
						}
						break;
					case 3: /* ifInDiscards */
						if (vars->type == ASN_COUNTER) {
							interfaces[j].inDiscards = *(vars->val.integer);
						}
						break;
					case 4: /* ifInErrors or locIfInCRC */
						if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER) {
							interfaces[j].inErrors = *(vars->val.integer);
						}
						break;
					case 5: /* ifOutOctets */
						if (vars->type == ASN_COUNTER) {
							interfaces[j].outOctets = *(vars->val.integer);
						}
						break;
					case 6: /* ifOutDiscards */
						if (vars->type == ASN_COUNTER) {
							interfaces[j].outDiscards = *(vars->val.integer);
						}
						break;
					case 7: /* ifOutErrors or locIfCollisions */
						if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER) {
							interfaces[j].outErrors = *(vars->val.integer);
						}
						break;
					}
				}
				if (response) {
					snmp_free_pdu(response);
					response = 0;
				}
			}

			/* now fetch the extended oids (64 bit counters etc.) */
			if (create_request(snmp_session, &OIDp, oid_extended, interfaces[j].index, &response, config.sleep_usecs)) {
				for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable) {
					k = -1;
					/* compare the received value to the requested value */
					for (int i = 0; oid_extended[i]; i++) {
						if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len * sizeof(oid))) {
							k = i;
							break;
						}
					}

					switch (k) /* the offset into oid_extended */
					{
					case 0: /* ifHCInOctets */
						if (vars->type == ASN_COUNTER64) {
							interfaces[j].inOctets = convertto64((vars->val.counter64), 0);
						}
						break;
					case 1: /* ifHCOutOctets */
						if (vars->type == ASN_COUNTER64) {
							interfaces[j].outOctets = convertto64((vars->val.counter64), 0);
						}
						break;
					case 2: /* ifInUcastPkts */
						if (vars->type == ASN_COUNTER) {
							interfaces[j].inUcast = *(vars->val.integer);
						}
						break;
					case 3: /* ifOutUcastPkts */
						if (vars->type == ASN_COUNTER) {
							interfaces[j].outUcast = *(vars->val.integer);
						}
						break;
					case 4: /* ifSpeed */
						/* don't overwrite a high-speed value */
						if (vars->type == ASN_GAUGE && !(interfaces[j].speed)) {
							interfaces[j].speed = *(vars->val.integer);
						}
						break;
					case 5: /* ifHighSpeed */
						if (vars->type == ASN_GAUGE) {
							/* convert to bits / sec */
							interfaces[j].speed = ((unsigned long long)*(vars->val.integer)) * 1000000ULL;
						}
						break;
					case 6: /* alias */
						if (vars->type == ASN_OCTET_STR) {
							MEMCPY(interfaces[j].alias, vars->val.string, vars->val_len);
						}
						break;
					case 7: /* name */
						if (vars->type == ASN_OCTET_STR) {
							MEMCPY(interfaces[j].name, vars->val.string, vars->val_len);
						}
						break;
					}
				}
				if (response) {
					snmp_free_pdu(response);
					response = 0;
				}
			}

			/* now fetch the Cisco-specific extended oids */
			if (config.mode == CISCO &&
				create_request(snmp_session, &OIDp, oid_extended_cisco, interfaces[j].index, &response, config.sleep_usecs)) {
				for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable) {
					k = -1;
					/* compare the received value to the requested value */
					for (int i = 0; oid_extended_cisco[i]; i++) {
						if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len * sizeof(oid))) {
							k = i;
							break;
						}
					}

					switch (k) /* the offset into oid_extended_cisco */
					{
					case 0: /* portAdditionalOperStatus */
						if (vars->type == ASN_OCTET_STR) {
							interfaces[j].err_disable = !!(vars->val.string[1] & (unsigned char)32U);
						}
						break;
					}
				}
				if (response) {
					snmp_free_pdu(response);
					response = 0;
				}
			}
		}
	}

	/* let the user know about interfaces that are down (and subsequently
	 * ignored)
	 */
	if (ignore_count) {
		addstr(&out, " - %d %s administratively down", ignore_count, ignore_count != 1 ? "are" : "is");
	}

	if (OIDp) {
		free(OIDp);
		OIDp = 0;
	}

	/* calculate time taken, print perfdata */

	gettimeofday(&time_value, &time_zone);

	returncode_t exit_code = print_output(&config, oldperfdata, starttime, interfaces, &out, if_vars, count, &time_value, uptime, ifNumber);

#ifdef DEBUG
	benchmark_start("Close SNMP session");
#endif
	snmp_close(snmp_session);
	snmp_close(&session);
#ifdef DEBUG
	benchmark_end();
#endif

	SOCK_CLEANUP;
	exit(exit_code);
}

returncode_t print_output(struct configuration_struct *config, struct ifStruct *oldperfdata, long double starttime,
						  struct ifStruct *interfaces, String *out, char **if_vars, unsigned int number_of_matched_interfaces,
						  struct timeval *time_value, int uptime, int ifNumber) {

	unsigned int parsed_lastcheck = 0;

	if (config->oldperfdatap && config->oldperfdatap[0]) {
		parse_perfdata(config->oldperfdatap, oldperfdata, config->prefix, &parsed_lastcheck, ifNumber, if_vars);
	}

	if (config->lastcheck) {
		config->lastcheck = (starttime - config->lastcheck);
	} else if (parsed_lastcheck) {
		config->lastcheck = (starttime - parsed_lastcheck);
	}

	/* do not use old perfdata if the device has been reset recently
	 * Note that a switch will typically rollover the uptime counter every 497
	 * days which is infrequent enough to not bother about :-)
	 * UPTIME_TOLERANCE_IN_SECS doesn't need to be a big number
	 */
	if ((config->lastcheck + UPTIME_TOLERANCE_IN_SECS) > uptime) {
		config->lastcheck = 0;
	}

	char perfstr[MAX_STRING];
	memset(perfstr, 0, sizeof(perfstr));
	String perf;
	perf.max = MAX_STRING;
	perf.len = 0;
	perf.text = perfstr;

	bool errorflag = false;
	bool warnflag = false;

	for (int i = 0; i < ifNumber; i++) {
		double inload = 0;
		double outload = 0;
		if (!interfaces[i].ignore) {
			int warn = 0;

			char *nameOrDescr = config->get_names_flag && strlen(interfaces[i].name) ? interfaces[i].name : interfaces[i].descr;

			if ((!interfaces[i].status || interfaces[i].err_disable) && !interfaces[i].ignore && !interfaces[i].admin_down) {
				if (config->crit_on_down_flag) {
					addstr(&perf, "[CRITICAL] ");
					errorflag = true;
					/* show the alias if configured */
					if (config->get_names_flag && strlen(interfaces[i].name)) {
						addstr(out, ", %s", interfaces[i].name);
						addstr(&perf, "%s", interfaces[i].name);
					} else {
						addstr(out, ", %s", interfaces[i].descr);
						addstr(&perf, "%s", interfaces[i].descr);
					}
					if (!interfaces[i].admin_down) {
						if (config->get_aliases_flag && strlen(interfaces[i].alias)) {
							addstr(out, " (%s) down", interfaces[i].alias);
							addstr(&perf, " (%s) down", interfaces[i].alias);
						} else {
							addstr(out, " down");
							addstr(&perf, " down");
						}
						if (interfaces[i].err_disable) {
							addstr(out, " (errdisable)");
							addstr(&perf, " (errdisable)");
						}
					}
				} else {
					addstr(&perf, "[OK] ");
					if (config->get_names_flag && strlen(interfaces[i].name)) {
						addstr(&perf, "%s", interfaces[i].name);
					} else {
						addstr(&perf, "%s", interfaces[i].descr);
					}
					if (config->get_aliases_flag && strlen(interfaces[i].alias)) {
						addstr(&perf, " (%s) down", interfaces[i].alias);
					} else {
						addstr(&perf, " down");
					}
				}
			} else if (interfaces[i].admin_down && config->print_all_flag) {
				addstr(&perf, "[OK] %s", (config->get_names_flag && strlen(interfaces[i].name)) ? interfaces[i].name : interfaces[i].descr);
				if (config->get_aliases_flag && strlen(interfaces[i].alias)) {
					addstr(&perf, " (%s) is down (administrative down)", interfaces[i].alias);
				} else {
					addstr(&perf, " is down (administrative down)");
				}
			}

			/* check if errors on the interface are increasing faster than our
			   defined value */
			else if ((oldperfdata[i].inErrors || oldperfdata[i].outErrors) &&
					 (interfaces[i].inErrors > (oldperfdata[i].inErrors + (unsigned long)config->err_tolerance) ||
					  interfaces[i].outErrors > (oldperfdata[i].outErrors + (unsigned long)config->coll_tolerance))) {
				if (config->oldperfdatap && !interfaces[i].ignore) {
					if (config->get_names_flag && strlen(interfaces[i].name)) {
						addstr(&perf, "[WARNING] %s", interfaces[i].name);
					} else {
						addstr(&perf, "[WARNING] %s", interfaces[i].descr);
					}

					if (config->get_aliases_flag && strlen(interfaces[i].alias)) {
						addstr(&perf, " (%s) has", interfaces[i].alias);
					} else {
						addstr(&perf, " has");
					}

					/* if we are not in cisco mode simply use "errors" */

					if (config->mode != CISCO) {
						addstr(&perf, " errors\n");
					} else {
						if (interfaces[i].inErrors > (oldperfdata[i].inErrors + (unsigned long)config->err_tolerance)) {
							addstr(&perf, " %lu CRC errors since last check\n", interfaces[i].inErrors - oldperfdata[i].inErrors);
						}
						if (interfaces[i].outErrors > (oldperfdata[i].outErrors + (unsigned long)config->coll_tolerance)) {
							addstr(&perf, " %lu collisions since last check\n", interfaces[i].outErrors - oldperfdata[i].outErrors);
						}
					}
					if (config->get_names_flag && strlen(interfaces[i].name)) {
						addstr(out, ", %s has %lu errors", interfaces[i].name,
							   (interfaces[i].inErrors + interfaces[i].outErrors - oldperfdata[i].inErrors - oldperfdata[i].outErrors));
					} else {
						addstr(out, ", %s has %lu errors", interfaces[i].descr,
							   (interfaces[i].inErrors + interfaces[i].outErrors - oldperfdata[i].inErrors - oldperfdata[i].outErrors));
					}
					warnflag = true;
					// warn++; /* if you uncomment this you will get 2 rows with
					// [warning]
					// */
				}
			}

			if (config->lastcheck && (interfaces[i].speed || config->speed) && !interfaces[i].admin_down &&
				(oldperfdata[i].inOctets || oldperfdata[i].outOctets)) {
				interfaces[i].inbitps = (subtract64(interfaces[i].inOctets, oldperfdata[i].inOctets, config->lastcheck, uptime) /
										 (unsigned long long)config->lastcheck) *
										8ULL;
				interfaces[i].outbitps = (subtract64(interfaces[i].outOctets, oldperfdata[i].outOctets, config->lastcheck, uptime) /
										  (unsigned long long)config->lastcheck) *
										 8ULL;
				if (config->speed) {
					inload = (long double)interfaces[i].inbitps / ((long double)config->speed / 100L);
					outload = (long double)interfaces[i].outbitps / ((long double)config->speed / 100L);
				} else {
					/* use the interface speed if a speed is not given */
					inload = (long double)interfaces[i].inbitps / ((long double)interfaces[i].speed / 100L);
					outload = (long double)interfaces[i].outbitps / ((long double)interfaces[i].speed / 100L);
				}

				if ((config->bandwith > 0) && ((int)inload > config->bandwith || (int)outload > config->bandwith)) {
					warn++;
					warnflag = true;
				}
			}

			if (interfaces[i].status && !interfaces[i].ignore) {
				if (!(warn)) {
					addstr(&perf, "[OK]");
				} else {
					addstr(&perf, "[WARNING]");
				}

				addstr(&perf, " %s", nameOrDescr);

				if (config->get_aliases_flag && strlen(interfaces[i].alias)) {
					addstr(&perf, " (%s)", interfaces[i].alias);
				}
				addstr(&perf, " is up");
			}

			if (config->lastcheck && (interfaces[i].speed || config->speed) &&
				(interfaces[i].inbitps > 0ULL || interfaces[i].outbitps > 0ULL) && !interfaces[i].admin_down) {
				char *ins;
				char *outs;
				gauge_to_si(interfaces[i].inbitps, &ins);
				gauge_to_si(interfaces[i].outbitps, &outs);

				addstr(&perf, "   %sbps(%0.2f%%)/%sbps(%0.2f%%)", ins, inload, outs, outload);
				free(ins);
				free(outs);
			}
			if (perf.len > 0U && perf.text[(perf.len - 1U)] != '\n') {
				addstr(&perf, "\n");
			}
		}
	}

	if (errorflag) {
		printf("CRITICAL:");
	} else if (warnflag) {
		printf("WARNING:");
	} else {
		printf("OK:");
	}

	printf(" %d interface%s found", ifNumber, (ifNumber == 1) ? "" : "s");
	if (config->iface_regex) {
		printf(", of which %d matched the regex", number_of_matched_interfaces);
	}

	/* now print performance data */

	printf("%*s | interfaces::check_multi::plugins=%d time=%.2Lf checktime=%ld", (int)out->len, out->text, number_of_matched_interfaces,
		   (((long double)time_value->tv_sec + ((long double)time_value->tv_usec / 1000000)) - starttime), time_value->tv_sec);
	if (uptime) {
		printf(" %sdevice::check_snmp::uptime=%us", config->prefix ? config->prefix : "", uptime);
	}

	for (int i = 0; i < ifNumber; i++) {
		if (!interfaces[i].ignore && (!interfaces[i].admin_down || config->print_all_flag)) {
			printf(" %s%s::check_snmp::", config->prefix ? config->prefix : "", oldperfdata[i].descr);
			printf("%s=%lluc %s=%lluc", if_vars[0], interfaces[i].inOctets, if_vars[1], interfaces[i].outOctets);
			printf(" %s=%luc %s=%luc", if_vars[2], interfaces[i].inDiscards, if_vars[3], interfaces[i].outDiscards);
			printf(" %s=%luc %s=%luc", if_vars[4], interfaces[i].inErrors, if_vars[5], interfaces[i].outErrors);
			printf(" %s=%luc %s=%luc", if_vars[6], interfaces[i].inUcast, if_vars[7], interfaces[i].outUcast);
			if (config->speed) {
				printf(" %s=%llu", if_vars[8], config->speed);
			} else {
				printf(" %s=%llu", if_vars[8], interfaces[i].speed);
			}
			printf(" %s=%llub %s=%llub", if_vars[9], interfaces[i].inbitps, if_vars[10], interfaces[i].outbitps);
		}
	}
	printf("\n%*s", (int)perf.len, perf.text);

	if (errorflag) {
		return CRITICAL;
	}
	if (warnflag) {
		return WARNING;
	}
	return OK;
}

bool fetch_interface_aliases(struct configuration_struct *config, char **oid_aliasp, netsnmp_session *snmp_session,
							 netsnmp_session *session, struct ifStruct *interfaces, int ifNumber) {
	bool lastifflag = false;
	int count = 0;
	netsnmp_pdu *pdu;
	struct OIDStruct lastOid;
	netsnmp_pdu *response;

	/* allocate the space for the alias OIDs */
	struct OIDStruct *OIDp = (struct OIDStruct *)calloc(1, sizeof(struct OIDStruct));
	while (lastifflag == false) {

		/* build our request depending on the mode */
		if (count == 0) {
			create_pdu(config->mode, oid_aliasp, &pdu, &OIDp, 0, ifNumber);
		} else {
			/* we have not received all aliases in the preceding packet, so
			 * fetch the next lot */

			if (config->mode == BINTEC || config->mode == NONBULK) {
				pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
			} else {
				pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
				pdu->non_repeaters = 0;
				pdu->max_repetitions = ifNumber - count;
			}
			snmp_add_null_var(pdu, lastOid.name, lastOid.name_len);
		}

#ifdef DEBUG
		implode_result = implode(", ", oid_aliasp + count);
		benchmark_start("Send SNMP request for OIDs: %s", implode_result);
#endif
		/* send the request */
		int status;
		status = snmp_synch_response(snmp_session, pdu, &response);
#ifdef DEBUG
		benchmark_end();
		free(implode_result);
#endif
		if (config->sleep_usecs) {
			usleep(config->sleep_usecs);
		}

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

			netsnmp_variable_list *vars;
			vars = response->variables;

			for (; vars; vars = vars->next_variable) {
				/*
				 * if the next OID is shorter
				 * or if the next OID doesn't begin with our base OID
				 * then we have reached the end of the table :-)
				 * print_variable(vars->name, vars->name_length, vars);
				 */

				/* save the OID in case we need additional packets */
				memcpy(lastOid.name, vars->name, (vars->name_length * sizeof(oid)));
				lastOid.name_len = vars->name_length;

				if ((vars->name_length < OIDp[0].name_len) || (memcmp(OIDp[0].name, vars->name, (vars->name_length - 1) * sizeof(oid)))) {
#ifdef DEBUG
					fprintf(stderr, "reached end of aliases\n");
#endif
					lastifflag = true;
					break;
				}

				/* now we fill our interfaces array with the alias
				 */
				if (vars->type == ASN_OCTET_STR) {
					int i = (int)vars->name[(vars->name_length - 1)];
					if (i) {
						MEMCPY(interfaces[count].alias, vars->val.string, vars->val_len);
						TERMSTR(interfaces[count].alias, vars->val_len);
					}
				}
				count++;
			}

			if (count < ifNumber) {
				if (lastifflag) {
#ifdef DEBUG
					fprintf(stderr,
							"Device has %d interfaces but only has %d "
							"aliases\n",
							ifNumber, count);
#endif
				} else {
#ifdef DEBUG
					fprintf(stderr, "Sending another packet for aliases\n");
#endif
				}
			} else {
				lastifflag = true;
			}
		} else {
			/*
			 * FAILURE: print what went wrong!
			 */

			if (status == STAT_SUCCESS) {
				printf("Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
			} else if (status == STAT_TIMEOUT) {
				printf("Timeout while reading interface aliases from %s\n", (*session).peername);
				exit(EXITCODE_TIMEOUT);
			} else {
				snmp_sess_perror("snmp_bulkget", snmp_session);
			}
			exit(2);
		}
		/*
		 * Clean up:
		 *   free the response.
		 */
		if (response) {
			snmp_free_pdu(response);
			response = 0;
		}
	}
	return true;
}

bool fetch_interface_names(struct configuration_struct *config, char **oid_namesp, netsnmp_session *snmp_session, netsnmp_session *session,
						   struct ifStruct *interfaces, int ifNumber) {
	bool lastifflag = false;
	netsnmp_pdu *pdu;
	struct OIDStruct lastOid;
	netsnmp_pdu *response;

	/* allocate the space for the names OIDs */
	struct OIDStruct *OIDp = (struct OIDStruct *)calloc(1, sizeof(struct OIDStruct));

	int count = 0;

	while (lastifflag == false) {

		/* build our request depending on the mode */
		if (count == 0) {
			create_pdu(config->mode, oid_namesp, &pdu, &OIDp, 0, ifNumber);
		} else {
			/* we have not received all names in the preceding packet, so
			 * fetch the next lot */

			if (config->mode == BINTEC || config->mode == NONBULK) {
				pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
			} else {
				pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
				pdu->non_repeaters = 0;
				pdu->max_repetitions = ifNumber - count;
			}
			snmp_add_null_var(pdu, lastOid.name, lastOid.name_len);
		}

#ifdef DEBUG
		implode_result = implode(", ", oid_namesp + count);
		benchmark_start("Send SNMP request for OIDs: %s", implode_result);
#endif
		/* send the request */
		int status = snmp_synch_response(snmp_session, pdu, &response);
#ifdef DEBUG
		benchmark_end();
		free(implode_result);
#endif
		if (config->sleep_usecs) {
			usleep(config->sleep_usecs);
		}

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

			netsnmp_variable_list *vars = response->variables;

			for (; vars; vars = vars->next_variable) {
				/*
				 * if the next OID is shorter
				 * or if the next OID doesn't begin with our base OID
				 * then we have reached the end of the table :-)
				 * print_variable(vars->name, vars->name_length, vars);
				 */

				/* save the OID in case we need additional packets */
				memcpy(lastOid.name, vars->name, (vars->name_length * sizeof(oid)));
				lastOid.name_len = vars->name_length;

				if ((vars->name_length < OIDp[0].name_len) || (memcmp(OIDp[0].name, vars->name, (vars->name_length - 1) * sizeof(oid)))) {
#ifdef DEBUG
					fprintf(stderr, "reached end of names\n");
#endif
					lastifflag = true;
					break;
				}

				/* now we fill our interfaces array with the names
				 */
				if (vars->type == ASN_OCTET_STR) {
					int i = (int)vars->name[(vars->name_length - 1)];
					if (i) {
						MEMCPY(interfaces[count].name, vars->val.string, vars->val_len);
						TERMSTR(interfaces[count].name, vars->val_len);
					}
				}
				count++;
			}

			if (count < ifNumber) {
#ifdef DEBUG
				if (lastifflag) {
					fprintf(stderr, "Device has %d interfaces but only has %d names\n", ifNumber, count);
				} else {
					fprintf(stderr, "Sending another packet for names\n");
				}
#endif
			} else {
				lastifflag = true;
			}
		} else {
			/*
			 * FAILURE: print what went wrong!
			 */

			if (status == STAT_SUCCESS) {
				printf("Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
			} else if (status == STAT_TIMEOUT) {
				printf("Timeout while reading interface names from %s\n", (*session).peername);
				exit(EXITCODE_TIMEOUT);
			} else {
				snmp_sess_perror("snmp_bulkget", snmp_session);
			}
			exit(2);
		}
		/*
		 * Clean up:
		 *   free the response.
		 */
		if (response) {
			snmp_free_pdu(response);
			response = 0;
		}
	}

	return true;
}

enum {
	PORT_OPTION = CHAR_MAX + 1,
	VERSION_OPTION = CHAR_MAX + 2
};

void parse_and_check_commandline(int argc, char **argv, struct configuration_struct *config) {
	int opt;

	char *progname = strrchr(argv[0], '/');
	if (progname != NULL && *progname && *(progname + 1)) {
		progname++;
	} else {
		progname = "check_interfaces";
	}

	/* parse options */
	static struct option longopts[] = {{"aliases", no_argument, NULL, 'a'},
									   {"match-aliases", no_argument, NULL, 'A'},
									   {"bandwidth", required_argument, NULL, 'b'},
									   {"community", required_argument, NULL, 'c'},
									   {"down-is-ok", no_argument, NULL, 'd'},
									   {"errors", required_argument, NULL, 'e'},
									   {"out-errors", required_argument, NULL, 'f'},
									   {"hostname", required_argument, NULL, 'h'},
									   {"port", required_argument, NULL, PORT_OPTION},
									   {"auth-proto", required_argument, NULL, 'j'},
									   {"auth-phrase", required_argument, NULL, 'J'},
									   {"priv-proto", required_argument, NULL, 'k'},
									   {"priv-phrase", required_argument, NULL, 'K'},
									   {"mode", required_argument, NULL, 'm'},
									   {"perfdata", required_argument, NULL, 'p'},
									   {"prefix", required_argument, NULL, 'P'},
									   {"regex", required_argument, NULL, 'r'},
									   {"exclude-regex", required_argument, NULL, 'R'},
									   {"if-names", no_argument, NULL, 'N'},
									   {"debug-print", no_argument, NULL, 'D'},
									   {"speed", required_argument, NULL, 's'},
									   {"lastcheck", required_argument, NULL, 't'},
									   {"user", required_argument, NULL, 'u'},
									   {"trim", required_argument, NULL, 'x'},
									   {"help", no_argument, NULL, '?'},
									   {"timeout", required_argument, NULL, 2},
									   {"sleep", required_argument, NULL, 3},
									   {"retries", required_argument, NULL, 4},
									   {"max-repetitions", required_argument, NULL, 5},
									   {"version", no_argument, NULL, VERSION_OPTION},
									   {NULL, 0, NULL, 0}};

	while ((opt = getopt_long(argc, argv, "aAb:c:dDe:f:h:j:J:k:K:m:Np:P:r:R:s:t:u:x:?", longopts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			config->get_aliases_flag = true;
			break;
		case 'A':
			config->get_aliases_flag = true; /* we need to see what we have matched... */
			config->match_aliases_flag = true;
			break;
		case 'b':
			config->bandwith = strtol(optarg, NULL, 10);
			break;
		case 'c':
			config->community = optarg;
			break;
		case 'd':
			config->crit_on_down_flag = false;
			break;
		case 'D':
			config->print_all_flag = true;
			break;
		case 'e':
			config->err_tolerance = strtol(optarg, NULL, 10);
			break;
		case 'f':
			config->coll_tolerance = strtol(optarg, NULL, 10);
			break;
		case 'h':
			config->hostname = optarg;
			break;
		case PORT_OPTION:
			config->port = optarg;
			break;
		case 'j':
			config->auth_proto = optarg;
			break;
		case 'J':
			config->auth_pass = optarg;
			break;
		case 'k':
			config->priv_proto = optarg;
			break;
		case 'K':
			config->priv_pass = optarg;
			break;
		case 'm':
			/* mode switch */
			for (int i = 0; modes[i]; i++) {
				if (!strcmp(optarg, modes[i])) {
					config->mode = i;
					break;
				}
			}
			break;
		case 'N':
			config->get_names_flag = true;
			break;
		case 'p':
			config->oldperfdatap = optarg;
			break;
		case 'P':
			config->prefix = optarg;
			break;
		case 'r':
			config->iface_regex = optarg;
			break;
		case 'R':
			config->exclude_list = optarg;
			break;
		case 's':
			config->speed = strtoull(optarg, NULL, 10);
			break;
		case 't':
			config->lastcheck = strtol(optarg, NULL, 10);
			break;
		case 'u':
			config->user = optarg;
			break;
		case 'x':
			config->trimdescr = strtol(optarg, NULL, 10);
			break;
		case 2:
			/* convert from ms to us */
			config->global_timeout = strtol(optarg, NULL, 10) * 1000UL;
			break;
		case 3:
			/* convert from ms to us */
			config->sleep_usecs = strtol(optarg, NULL, 10) * 1000UL;
			break;
		case 4:
			config->session_retries = atoi(optarg);
			break;
		case 5:
			config->pdu_max_repetitions = strtol(optarg, NULL, 10);
			break;
		case VERSION_OPTION:
			print_version();
		case '?':
		default:
			exit(usage(progname));
		}
	}
	argc -= optind;
	argv += optind;

	if (config->coll_tolerance == -1) {
		/* set the outErrors tolerance to that of inErrors unless explicitly set
		 * otherwise */
		config->coll_tolerance = config->err_tolerance;
	}

	if (!(config->hostname)) {
		exit(usage(progname));
	}

#ifdef HAVE_GETADDRINFO
	struct addrinfo *addr_list;
	/* check for a valid hostname / IP Address */
	if (getaddrinfo(config->hostname, NULL, NULL, &addr_list)) {
		printf("Failed to resolve hostname %s\n", config->hostname);
		exit(3);
	}
	/* name is resolvable - pass it to the snmplib */
	freeaddrinfo(addr_list);
#endif /* HAVE_GETADDRINFO */

	if (!config->community) {
		config->community = DEFAULT_COMMUNITY;
	}

	if (config->exclude_list && !config->iface_regex) {
		/* use .* as the default regex */
		config->iface_regex = ".*";
	}

	/* get the start time */

	/* parse the interfaces regex */
	int status;
	if (config->iface_regex) {
		status = regcomp(&config->re, config->iface_regex, REG_ICASE | REG_EXTENDED | REG_NOSUB);
		if (status != 0) {
			printf("Error creating regex\n");
			exit(3);
		}

		if (config->exclude_list) {
			status = regcomp(&config->exclude_re, config->exclude_list, REG_ICASE | REG_EXTENDED | REG_NOSUB);
			if (status != 0) {
				printf("Error creating exclusion regex\n");
				exit(3);
			}
		}
	}

	/* set the MIB variable if it is unset to avoid net-snmp warnings */
	if (getenv("MIBS") == NULL) {
		setenv("MIBS", "", 1);
	}
}

void print_version(void) {
#ifdef PACKAGE_VERSION
	puts(PACKAGE_VERSION);
#endif // PACKAGE_VERSION
	exit(0);
}

int usage(char *progname) {
	printf(
#ifdef PACKAGE_STRING
		PACKAGE_STRING "\n\n"
#endif
					   "Usage: %s -h <hostname> [OPTIONS]\n",
		progname);

	printf(" -c|--community\t\tcommunity (default public)\n");
	printf(" -r|--regex\t\tinterface list regexp\n");
	printf(" -R|--exclude-regex\tinterface list negative regexp\n");
	printf(" -e|--errors\t\tnumber of in errors (CRC errors for cisco) to "
		   "consider a warning (default 50)\n");
	printf(" -f|--out-errors\tnumber of out errors (collisions for cisco) to "
		   "consider a warning (default same as in errors)\n");
	printf(" -p|--perfdata\t\tlast check perfdata\n");
	printf(" -P|--prefix\t\tprefix interface names with this label\n");
	printf(" -t|--lastcheck\t\tlast checktime (unixtime)\n");
	printf(" -b|--bandwidth\t\tbandwidth warn level in %%\n");
	printf(" -s|--speed\t\toverride speed detection with this value (bits per "
		   "sec)\n");
	printf(" -x|--trim\t\tcut this number of characters from the start of "
		   "interface descriptions\n");
	printf(" -m|--mode\t\tspecial operating mode (");
	for (int i = 0; modes[i]; i++) {
		printf("%s%s", i ? "," : "", modes[i]);
	}
	printf(")\n");
	printf(" -j|--auth-proto\tSNMPv3 Auth Protocol (SHA|SHA-224|SHA-256|SHA-384|SHA-512|MD5)\n");
	printf(" -J|--auth-phrase\tSNMPv3 Auth Phrase\n");
#ifdef HAVE_USM_DES_PRIV_PROTOCOL
	printf(" -k|--priv-proto\tSNMPv3 Privacy Protocol (AES|DES), unset means not "
		   "privacy protocol!\n");
#else
	printf(" -k|--priv-proto\tSNMPv3 Privacy Protocol (AES), unset means not "
		   "privacy protocol!\n");
#endif
	printf(" -K|--priv-phrase\tSNMPv3 Privacy Phrase\n");
	printf(" -u|--user\t\tSNMPv3 User\n");
	printf(" -d|--down-is-ok\tdisables critical alerts for down interfaces\n");
	printf(" -a|--aliases\t\tretrieves the interface description\n");
	printf(" -A|--match-aliases\talso match against aliases (Option -a "
		   "automatically enabled)\n");
	printf(" -D|--debug-print\tlist administrative down interfaces in perfdata\n");
	printf(" -N|--if-names\t\tuse ifName instead of ifDescr\n");
	printf("    --timeout\t\tsets the SNMP timeout (in ms)\n");
	printf("    --sleep\t\tsleep between every SNMP query (in ms)\n");
	printf("    --retries\t\thow often to retry before giving up\n");
	printf("    --max-repetitions\t\tsee "
		   "<http://www.net-snmp.org/docs/man/snmpbulkwalk.html>\n");
	printf("    --port\t\tPort (default 161)\n");
	printf("    --version\t\tPrint program version\n");
	printf("\n");
	return 3;
}
