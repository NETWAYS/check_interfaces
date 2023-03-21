/*
 *
 * COPYRIGHT:
 *
 * This software is Copyright (c) 2011,2012 NETWAYS GmbH, William Preston
 *                                <support@netways.de>
 *
 * (Except where explicitly superseded by other copyright notices)
 *
 *
 * LICENSE:
 *
 * This work is made available to you under the terms of Version 2 of
 * the GNU General Public License. A copy of that license should have
 * been provided with this software, but in any event can be snarfed
 * from http://www.fsf.org.
 *
 * This work is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 or visit their web page on the internet at
 * http://www.fsf.org.
 *
 *
 * CONTRIBUTION SUBMISSION POLICY:
 *
 * (The following paragraph is not intended to limit the rights granted
 * to you to modify and distribute this software under the terms of
 * the GNU General Public License and is only of importance to you if
 * you choose to contribute your changes and enhancements to the
 * community by submitting them to NETWAYS GmbH.)
 *
 * By intentionally submitting any modifications, corrections or
 * derivatives to this work, or any other work intended for use with
 * this Software, to NETWAYS GmbH, you confirm that
 * you are the copyright holder for those contributions and you grant
 * NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
 * royalty-free, perpetual, license to use, copy, create derivative
 * works based on those contributions, and sublicense and distribute
 * those contributions and any derivatives thereof.
 *
 *
 *
 */

/* asprintf and getopt_long */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>

#include <limits.h>
#include <net-snmp/net-snmp-config.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

/* getenv */
#include <stdlib.h>

/* getopt_long */
#include <getopt.h>

#include "snmp_bulkget.h"

/*
 * operating modes
 */
const char *modes[] = {"default", "cisco", "nonbulk", "bintec", NULL};

/*
 * text strings to output in the perfdata
 */

char *if_vars_default[] = {"inOctets", "outOctets", "inDiscards", "outDiscards",
						   "inErrors", "outErrors", "inUcast",	  "outUcast",
						   "speed",	   "inBitps",	"outBitps"};

char *if_vars_cisco[] = {"inOctets",	"outOctets", "inDiscards",
						 "outDiscards", "inCRCs",	 "outCollisions",
						 "inUcast",		"outUcast",	 "speed",
						 "inBitps",		"outBitps"};

/*
 * OIDs, hardcoded to remove the dependency on MIBs
 */
char *oid_if_bulkget[] = {".1.3.6.1.2.1.1.3", ".1.3.6.1.2.1.2.1",
						  ".1.3.6.1.2.1.2.2.1.2",
						  0}; /* "uptime", "ifNumber", "ifDescr" */

size_t sizeof_oid_if_bulkget(void) { return sizeof(oid_if_bulkget); }

char *oid_if_get[] = {".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.1.0",
					  ".1.3.6.1.2.1.2.2.1.2.1",
					  0}; /* "uptime", "ifNumber", "ifDescr" */

size_t sizeof_oid_if_get(void) { return sizeof(oid_if_get); }

char *oid_if_bintec[] = {".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.1.0",
						 ".1.3.6.1.2.1.2.2.1.2.0",
						 0}; /* "uptime", "ifNumber", "ifDescr" */

size_t sizeof_oid_if_bintec(void) { return sizeof(oid_if_bintec); }

char *oid_alias_bulkget[] = {".1.3.6.1.2.1.31.1.1.1.18", 0};  /* "alias" */
char *oid_alias_get[] = {".1.3.6.1.2.1.31.1.1.1.18.1", 0};	  /* "alias" */
char *oid_alias_bintec[] = {".1.3.6.1.2.1.31.1.1.1.18.0", 0}; /* "alias" */
char *oid_names_bulkget[] = {".1.3.6.1.2.1.31.1.1.1.1", 0};	  /* "name" */
char *oid_names_get[] = {".1.3.6.1.2.1.31.1.1.1.1.1", 0};	  /* "name" */
char *oid_names_bintec[] = {".1.3.6.1.2.1.31.1.1.1.1.0",
							0}; /* "name - NOT TESTED!" */

char *oid_vals_default[] = {".1.3.6.1.2.1.2.2.1.7",	 /* ifAdminStatus */
							".1.3.6.1.2.1.2.2.1.8",	 /* ifOperStatus */
							".1.3.6.1.2.1.2.2.1.10", /* ifInOctets */
							".1.3.6.1.2.1.2.2.1.13", /* ifInDiscards */
							".1.3.6.1.2.1.2.2.1.14", /* ifInErrors */
							".1.3.6.1.2.1.2.2.1.16", /* ifOutOctets */
							".1.3.6.1.2.1.2.2.1.19", /* ifOutDiscards */
							".1.3.6.1.2.1.2.2.1.20", /* ifOutErrors */
							0};

char *oid_vals_cisco[] = {".1.3.6.1.2.1.2.2.1.7",	   /* ifAdminStatus */
						  ".1.3.6.1.2.1.2.2.1.8",	   /* ifOperStatus */
						  ".1.3.6.1.2.1.2.2.1.10",	   /* ifInOctets */
						  ".1.3.6.1.2.1.2.2.1.13",	   /* ifInDiscards */
						  ".1.3.6.1.4.1.9.2.2.1.1.12", /* locIfInCRC */
						  ".1.3.6.1.2.1.2.2.1.16",	   /* ifOutOctets */
						  ".1.3.6.1.2.1.2.2.1.19",	   /* ifOutDiscards */
						  ".1.3.6.1.4.1.9.2.2.1.1.25", /* locIfCollisions */
						  0};

char *oid_extended[] = {".1.3.6.1.2.1.31.1.1.1.6",	/* ifHCInOctets */
						".1.3.6.1.2.1.31.1.1.1.10", /* ifHCOutOctets */
						".1.3.6.1.2.1.2.2.1.11",	/* ifInUcastPkts */
						".1.3.6.1.2.1.2.2.1.17",	/* ifOutUcastPkts */
						".1.3.6.1.2.1.2.2.1.5",		/* ifSpeed */
						".1.3.6.1.2.1.31.1.1.1.15", /* ifHighSpeed */
						".1.3.6.1.2.1.31.1.1.1.18", /* alias */
						".1.3.6.1.2.1.31.1.1.1.1",	/* name */
						0};

char *oid_extended_cisco[] = {
	".1.3.6.1.4.1.9.5.1.4.1.1.23", /* portAdditionalOperStatus */
	0};

char default_community[] = "public";

/* we assume that the index number is the same as the last digit of the OID
 * which may not always hold true...
 * but seems to do so in practice
 *
 *  input error checking
 *  index parameter support
 *  auto-detect hardware and switch mode
 *  make non-posix code optional e.g. asprintf
 */

/* uptime counter */
unsigned int uptime = 0;
unsigned int parsed_lastcheck = 0;

int ifNumber = 0;

#ifdef DEBUG
static char *implode_result;
#endif

void print64(struct counter64 *count64, unsigned long *count32) {

	if (!(isZeroU64(count64))) {
		char buffer[I64CHARSZ + 1];
		printU64(buffer, count64);
#ifdef DEBUG
		printf("64:%s", buffer);
#else
		printf("%s", buffer);
#endif
	} else {
#ifdef DEBUG
		printf("32:%lu", *count32);
#else
		printf("%lu", *count32);
#endif
	}
}

u64 convertto64(struct counter64 *val64, unsigned long *val32) {
	u64 temp64;

	if ((isZeroU64(val64))) {
		if (val32)
			temp64 = (u64)(*val32);
		else
			temp64 = 0;
	} else
		temp64 = ((u64)(val64->high) << 32) + val64->low;

	return (temp64);
}

u64 subtract64(u64 big64, u64 small64, unsigned int lastcheck) {
	if (big64 < small64) {
		/* either the device was reset or the counter overflowed
		 */
		if ((lastcheck + UPTIME_TOLERANCE_IN_SECS) > uptime)
			/* the device was reset, or the uptime counter rolled over
			 * so play safe and return 0 */
			return 0;
		else {
			/* we assume there was exactly 1 counter rollover
			 * - of course there may have been more than 1 if it
			 * is a 32 bit counter ...
			 */
			if (small64 > OFLO32)
				return (OFLO64 - small64 + big64);
			else
				return (OFLO32 - small64 + big64);
		}
	} else
		return (big64 - small64);
}

netsnmp_session *start_session(netsnmp_session *session, char *community,
							   char *hostname, enum mode_enum mode,
							   unsigned long global_timeout,
							   int session_retries) {
	netsnmp_session *ss;

	/*
	 * Initialize the SNMP library
	 */
	init_snmp("snmp_bulkget");

	/* setup session to hostname */
	snmp_sess_init(session);
	session->peername = hostname;

	/* bulk gets require V2c or later */
	if (mode == NONBULK)
		session->version = SNMP_VERSION_1;
	else
		session->version = SNMP_VERSION_2c;

	session->community = (u_char *)community;
	session->community_len = strlen(community);
	session->timeout = global_timeout;
	session->retries = session_retries;

	/*
	 * Open the session
	 */
	SOCK_STARTUP;
	ss = snmp_open(session); /* establish the session */

	if (!ss) {
		snmp_sess_perror("snmp_bulkget", session);
		SOCK_CLEANUP;
		exit(1);
	}

	return (ss);
}

netsnmp_session *start_session_v3(netsnmp_session *session, char *user,
								  char *auth_proto, char *auth_pass,
								  char *priv_proto, char *priv_pass,
								  char *hostname, unsigned long global_timeout,
								  int session_retries) {
	netsnmp_session *ss;

	init_snmp("snmp_bulkget");

	snmp_sess_init(session);
	session->peername = hostname;

	session->version = SNMP_VERSION_3;

	session->securityName = user;
	session->securityModel = SNMP_SEC_MODEL_USM;
	session->securityNameLen = strlen(user);

	if (priv_proto && priv_pass) {
		if (!strcmp(priv_proto, "AES")) {
			session->securityPrivProto = snmp_duplicate_objid(
				usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
			session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
#ifdef usmDESPrivProtocol
		} else if (!strcmp(priv_proto, "DES")) {
			session->securityPrivProto = snmp_duplicate_objid(
				usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
			session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#endif
		} else {
			printf("Unknown priv protocol %s\n", priv_proto);
			exit(3);
		}
		session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session->securityPrivKeyLen = USM_PRIV_KU_LEN;
	} else {
		session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		session->securityPrivKeyLen = 0;
	}

	if (auth_proto && auth_pass) {
		if (!strcmp(auth_proto, "SHA")) {
			session->securityAuthProto = snmp_duplicate_objid(
				usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
			session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		} else if (!strcmp(auth_proto, "MD5")) {
			session->securityAuthProto = snmp_duplicate_objid(
				usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
			session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		} else {
			printf("Unknown auth protocol %s\n", auth_proto);
			exit(3);
		}
		session->securityAuthKeyLen = USM_AUTH_KU_LEN;
	} else {
		session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		session->securityAuthKeyLen = 0;
		session->securityPrivKeyLen = 0;
	}

	if ((session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) ||
		(session->securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV)) {
		if (generate_Ku(session->securityAuthProto,
						session->securityAuthProtoLen,
						(unsigned char *)auth_pass, strlen(auth_pass),
						session->securityAuthKey,
						&session->securityAuthKeyLen) != SNMPERR_SUCCESS)
			printf("Error generating AUTH sess\n");
		if (session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
			if (generate_Ku(session->securityAuthProto,
							session->securityAuthProtoLen,
							(unsigned char *)priv_pass, strlen(priv_pass),
							session->securityPrivKey,
							&session->securityPrivKeyLen) != SNMPERR_SUCCESS)
				printf("Error generating PRIV sess\n");
		}
	}

	session->timeout = global_timeout;
	session->retries = session_retries;

	/*
	 * Open the session
	 */
	SOCK_STARTUP;
	ss = snmp_open(session); /* establish the session */

	if (!ss) {
		snmp_sess_perror("snmp_bulkget", session);
		SOCK_CLEANUP;
		exit(1);
	}

	return (ss);
}

int usage(char *progname) {
	int i;
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
	for (i = 0; modes[i]; i++) {
		printf("%s%s", i ? "," : "", modes[i]);
	}
	printf(")\n");
	printf(" -j|--auth-proto\tSNMPv3 Auth Protocol (SHA|MD5)\n");
	printf(" -J|--auth-phrase\tSNMPv3 Auth Phrase\n");
#ifdef usmDESPrivProtocol
	printf(
		" -k|--priv-proto\tSNMPv3 Privacy Protocol (AES|DES), unset means not "
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
	printf(
		" -D|--debug-print\tlist administrative down interfaces in perfdata\n");
	printf(" -N|--if-names\t\tuse ifName instead of ifDescr\n");
	printf("    --timeout\t\tsets the SNMP timeout (in ms)\n");
	printf("    --sleep\t\tsleep between every SNMP query (in ms)\n");
	printf("    --retries\t\thow often to retry before giving up\n");
	printf("    --max-repetitions\t\tsee "
		   "<http://www.net-snmp.org/docs/man/snmpbulkwalk.html>\n");
	printf("\n");
	return 3;
}

/*
 * tokenize a string containing performance data and fill a struct with
 * the individual variables
 *
 * e.g.  interfaces::check_multi::plugins=2 time=0.07
 * 11::check_snmp::inOctets=53273084427c outOctets=6370502528c inDiscards=0c
 * outDiscards=3921c inErrors=3c outErrors=20165c inUcast=38550136c
 * outUcast=21655535c speed=100000000 21::check_snmp::inOctets=5627677780c
 * outOctets=15023959911c inDiscards=0c outDiscards=0c inErrors=0c
 * outErrors=5431c inUcast=34020897c outUcast=35875426c speed=1000000000
 */
int parse_perfdata(char *oldperfdatap, struct ifStruct *oldperfdata,
				   char *prefix, unsigned int *parsed_lastcheck,
				   enum mode_enum mode) {
	char *last = 0, *last2 = 0, *word, *interface = 0, *var;
	char *ptr;
#ifdef DEBUG
	int plugins;
	int uptime_old;
#endif
	u64 value = 0;
	char *valstr;

	/* first split at spaces */
	for (word = strtok_r(oldperfdatap, " ", &last); word;
		 word = strtok_r(NULL, " ", &last)) {
		if ((ptr = strstr(word, "::check_multi::plugins="))) {
#ifdef DEBUG
			/* check multi perfdata found */
			plugins = strtol(strchr(word, '=') + 1, NULL, 10);
			fprintf(stderr, "Found %d plugins\n", plugins);
#endif
			continue;
		}

		if ((ptr = strstr(word, "checktime="))) {
			/* last checktime found */
			*parsed_lastcheck = strtol(strchr(word, '=') + 1, NULL, 10);
#ifdef DEBUG
			fprintf(stderr, "Found last checktime: %d\n", *parsed_lastcheck);
#endif
			continue;
		}

		if ((ptr = strstr(word, "device::check_snmp::"))) {
#ifdef DEBUG
			/* uptime found */
			uptime_old = strtol(strchr(word, '=') + 1, NULL, 10);
			fprintf(stderr, "Found %u uptime\n", uptime_old);
#endif
			continue;
		}

		if ((ptr = strstr(word, "::check_snmp::"))) {
			/* new interface found, get its name (be aware that this is the
			 * "cleaned" string */
			interface = strtok_r(word, ":", &last2);

			/* remove any prefix */
			if (prefix) {
				if (strlen(interface) > strlen(prefix))
					interface = interface + strlen(prefix);
			}
#ifdef DEBUG
			if (interface)
				fprintf(stderr, "interface %s found\n", interface);
#endif
			word = (ptr + strlen("::check_snmp::"));
		}

		/* finally split the name=value pair */
		valstr = strchr(word, '=');
		if (valstr)
			value = strtoull(valstr + 1, NULL, 10);

		var = strtok_r(word, "=", &last2);

		if (interface && var && valstr)
			set_value(oldperfdata, interface, var, value, mode);
	}

	return (0);
}

/*
 * fill the ifStruct with values
 */
void set_value(struct ifStruct *oldperfdata, char *interface, char *var,
			   u64 value, enum mode_enum mode) {
	int i;
	static char **if_vars;

	if (mode == CISCO)
		if_vars = if_vars_cisco;
	else
		if_vars = if_vars_default;

	for (i = 0; i < ifNumber; i++) {
		if (strcmp(interface, oldperfdata[i].descr) == 0) {
			if (strcmp(var, if_vars[0]) == 0)
				oldperfdata[i].inOctets = value;
			else if (strcmp(var, if_vars[1]) == 0)
				oldperfdata[i].outOctets = value;
			else if (strcmp(var, if_vars[2]) == 0)
				oldperfdata[i].inDiscards = value;
			else if (strcmp(var, if_vars[3]) == 0)
				oldperfdata[i].outDiscards = value;
			else if (strcmp(var, if_vars[4]) == 0)
				oldperfdata[i].inErrors = value;
			else if (strcmp(var, if_vars[5]) == 0)
				oldperfdata[i].outErrors = value;
			else if (strcmp(var, if_vars[6]) == 0)
				oldperfdata[i].inUcast = value;
			else if (strcmp(var, if_vars[7]) == 0)
				oldperfdata[i].outUcast = value;
			else if (strcmp(var, if_vars[8]) == 0)
				oldperfdata[i].speed = value;
			else if (strcmp(var, if_vars[9]) == 0)
				oldperfdata[i].inbitps = value;
			else if (strcmp(var, if_vars[10]) == 0)
				oldperfdata[i].outbitps = value;

			continue;
		}
	}
}

/*
 * pass this function a list of OIDs to retrieve
 * and it will fetch them with a single get
 */
int create_request(netsnmp_session *ss, struct OIDStruct **OIDpp,
				   char **oid_list, int index, netsnmp_pdu **response,
				   unsigned int sleep_usecs) {
	netsnmp_pdu *pdu;
	int status, i;
	struct OIDStruct *OIDp;

	/* store all the parsed OIDs in a structure for easy comparison */
	for (i = 0; oid_list[i]; i++)
		;
	OIDp = (struct OIDStruct *)calloc(i, sizeof(*OIDp));

	/* here we are retrieving single values, not walking the table */
	pdu = snmp_pdu_create(SNMP_MSG_GET);

	for (i = 0; oid_list[i]; i++) {
#ifdef DEBUG2
		fprintf(stderr, "%d: adding %s\n", i, oid_list[i]);
#endif
		OIDp[i].name_len = MAX_OID_LEN;
		parseoids(i, oid_list[i], OIDp);
		OIDp[i].name[OIDp[i].name_len++] = index;
		snmp_add_null_var(pdu, OIDp[i].name, OIDp[i].name_len);
	}
	pdu->non_repeaters = i;
	pdu->max_repetitions = 0;

	*OIDpp = OIDp;

#ifdef DEBUG
	implode_result = implode(", ", oid_list);
	benchmark_start("Send SNMP request for OIDs: %s", implode_result);
#endif
	status = snmp_synch_response(ss, pdu, response);
#ifdef DEBUG
	benchmark_end();
	free(implode_result);
#endif
	if (sleep_usecs)
		usleep(sleep_usecs);

	if (status == STAT_SUCCESS && (*response)->errstat == SNMP_ERR_NOERROR) {
		return (1);
	} else if (status == STAT_SUCCESS &&
			   (*response)->errstat == SNMP_ERR_NOSUCHNAME) {
		/* if e.g. 64 bit counters are not supported, we will get this error */
		return (1);
	} else {
		/*
		 * FAILURE: print what went wrong!
		 */

		if (status == STAT_SUCCESS)
			printf("Error in packet\nReason: %s\n",
				   snmp_errstring((*response)->errstat));
		else if (status == STAT_TIMEOUT) {
			printf("Timeout fetching interface stats from %s ", ss->peername);
			for (i = 0; oid_list[i]; i++) {
				printf("%c%s", i ? ',' : '(', oid_list[i]);
			}
			printf(")\n");
			exit(EXITCODE_TIMEOUT);
		} else {
			printf("other error\n");
			snmp_sess_perror("snmp_bulkget", ss);
		}
		exit(2);
	}

	return (0);
}

int parseoids(int i, char *oid_list, struct OIDStruct *query) {
	/* parse oid list
	 *
	 * read each OID from our array and add it to the pdu request
	 */

	query[i].name_len = MAX_OID_LEN;
	if (!snmp_parse_oid(oid_list, query[i].name, &query[i].name_len)) {
		snmp_perror(oid_list);
		SOCK_CLEANUP;
		exit(1);
	}
	return (0);
}

void create_pdu(int mode, char **oidlist, netsnmp_pdu **pdu,
				struct OIDStruct **oids, int nonrepeaters, long max) {
	int i;

	if (mode == NONBULK)
		*pdu = snmp_pdu_create(SNMP_MSG_GET);

	else if (mode == BINTEC) {
		/* we cannot use a bulk get for bintec
		 * and the oids don't increment properly
		 */
		*pdu = snmp_pdu_create(SNMP_MSG_GET);
	} else {
		/* get the ifNumber and as many interfaces as possible */
		*pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
		(*pdu)->non_repeaters = nonrepeaters;
		(*pdu)->max_repetitions = max;
	}

	for (i = 0; oidlist[i]; i++) {
		parseoids(i, oidlist[i], *oids);
		snmp_add_null_var(*pdu, (*oids)[i].name, (*oids)[i].name_len);
	}
}
