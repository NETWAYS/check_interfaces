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

#include <stdbool.h>


#include <net-snmp/net-snmp-config.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>

/* getenv */
#include <stdlib.h>

/* getopt_long */
#include <getopt.h>

#include "snmp_bulkget.h"
#include "utils.h"


/* we assume that the index number is the same as the last digit of the OID
 * which may not always hold true...
 * but seems to do so in practice
 *
 *  input error checking
 *  index parameter support
 *  auto-detect hardware and switch mode
 *  make non-posix code optional e.g. asprintf
 */


void create_pdu(int, char **, netsnmp_pdu **, struct OIDStruct **, int, long);

/* Forward declaration of command line parsing */
void parse_and_check_commandline(int argc, char **argv, struct configuration_struct *config);


/* uptime counter */
unsigned int uptime = 0;
unsigned int parsed_lastcheck = 0;

static
int ifNumber = 0;

#ifdef DEBUG
static
char *implode_result;
#endif

int
main(int argc, char *argv[])
{
    netsnmp_session session, *ss;
    netsnmp_pdu    *pdu;
    netsnmp_pdu *response;

    netsnmp_variable_list *vars;
    int     status, status2;
    int     count = 0; /* used for: the number of interfaces we receive, the number of regex matches */
    int     j, k;
    int errorflag = 0;
    int warnflag = 0;
    int lastifflag = 0;
    size_t  size;

    struct configuration_struct config;
    config.crit_on_down_flag = true;
    config.get_aliases_flag = false;
    config.match_aliases_flag = false;
    config.get_names_flag = false;
    config.print_all_flag = false;
    config.community = default_community;
    config.bandwith = 0;
    config.oldperfdatap = 0;
    config.err_tolerance = 50;
    config.coll_tolerance = -1;
    config.hostname = 0;
    config.user = 0;
    config.auth_proto = 0;
    config.auth_pass = 0;
    config.priv_proto = 0;
    config.priv_pass = 0;
    config.trimdescr = 0;
    config.prefix = 0;
    config.list = 0;
    config.global_timeout = DFLT_TIMEOUT;
    config.exclude_list = 0;
    config.speed = 0;
    config.lastcheck = 0;
    config.sleep_usecs = 0;
    config.session_retries = 2;
    config.pdu_max_repetitions= 4096L;

    config.mode = DEFAULT;

    struct ifStruct *interfaces = NULL; /* current interface data */
    struct ifStruct *oldperfdata = NULL; /* previous check interface data */
    struct OIDStruct *OIDp;

    struct timeval tv;
    struct timezone tz;
    long double starttime;
    int ignore_count = 0;

    double inload = 0,outload = 0;
    char *ins, *outs;

    char outstr[MAX_STRING];
    memset(outstr, 0, sizeof(outstr));
    String out;
    out.max = MAX_STRING;
    out.len = 0;
    out.text = outstr;

    char perfstr[MAX_STRING];
    memset(perfstr, 0, sizeof(perfstr));
    String perf;
    perf.max = MAX_STRING;
    perf.len = 0;
    perf.text = perfstr;


    struct OIDStruct lastOid;

    static char **oid_ifp;
    static char **oid_vals;
    static char **if_vars;
    static char **oid_aliasp;
    static char **oid_namesp;

    oid_ifp = oid_if_bulkget;
    oid_vals = oid_vals_default;
    if_vars = if_vars_default;

    parse_and_check_commandline(argc, argv, &config);

    gettimeofday(&tv, &tz);
    starttime=(long double)tv.tv_sec + (((long double)tv.tv_usec)/1000000);

#ifdef DEBUG
    benchmark_start("Start SNMP session");
#endif
    if (config.user)
        /* use snmpv3 */
        ss=start_session_v3(&session, config.user, config.auth_proto, config.auth_pass, config.priv_proto, config.priv_pass, config.hostname, config.global_timeout,config.session_retries);
    else
        ss=start_session(&session, config.community, config.hostname, config.mode, config.global_timeout, config.session_retries);
#ifdef DEBUG
    benchmark_end();
#endif

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
    OIDp = (struct OIDStruct *) calloc(size, sizeof(struct OIDStruct));

    if (config.mode == CISCO) {
        if_vars = if_vars_cisco;
        oid_vals = oid_vals_cisco;
    }

    /* get the number of interfaces, and their index numbers
     *
     * We will attempt to get all the interfaces in a single packet
     * - which should manage about 64 interfaces.
     * If the end interface has not been reached, we fetch more packets - this is
     * necessary to work around buggy switches that lie about the ifNumber
     */

    while (lastifflag==0) {

        /* build our request depending on the mode */
        if (count==0)
            create_pdu(config.mode, oid_ifp, &pdu, &OIDp, 2, config.pdu_max_repetitions);
        else {
            /* we have not received all interfaces in the preceding packet, so fetch the next lot */

            if (config.mode == BINTEC || config.mode == NONBULK)
                pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
            else {
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
        status = snmp_synch_response(ss, pdu, &response);
#ifdef DEBUG
        benchmark_end();
        free(implode_result);
#endif
        if (config.sleep_usecs)
            usleep(config.sleep_usecs);

        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

            vars = response->variables;

            if (count==0) {
                /* assuming that the uptime and ifNumber come first */
                /*  on some devices the ifNumber is not available... */

                while (!ifNumber) {
                    if (!(memcmp(OIDp[0].name, vars->name, OIDp[0].name_len * sizeof(oid)))) {
                        /* uptime */
                        if (vars->type == ASN_TIMETICKS)
                            /* uptime is in 10ms units -> convert to seconds */
                            uptime = *(vars->val.integer) / 100;
                    } else if (!memcmp(OIDp[1].name, vars->name, OIDp[1].name_len * sizeof(oid))) {
                        /* we received a valid IfNumber */
                        ifNumber = *(vars->val.integer);
                        if (ifNumber == 0) {
                            /* there are no interfaces! Stop here */
                            printf("No interfaces found");
                            exit (0);
                        }
                    } else {
                        addstr(&out, "(no IfNumber parameter, assuming 32 interfaces) ");
                        ifNumber = 32;
                    }

                    vars = vars->next_variable;
                }

                interfaces = (struct ifStruct*)calloc((size_t)ifNumber, sizeof(struct ifStruct));
                oldperfdata = (struct ifStruct*)calloc((size_t)ifNumber, sizeof(struct ifStruct));

#ifdef DEBUG
                fprintf(stderr, "got %d interfaces\n", ifNumber);
#endif
            } else {
                /* subsequent replies have no ifNumber */
            }


            for (vars = vars; vars; vars = vars->next_variable) {
                /*
                 * if the next OID is shorter
                 * or if the next OID doesn't begin with our base OID
                 * then we have reached the end of the table :-)
                 * print_variable(vars->name, vars->name_length, vars);
                 */

                /* save the OID in case we need additional packets */
                memcpy(lastOid.name, vars->name, (vars->name_length  * sizeof(oid)));
                lastOid.name_len = vars->name_length;

                if ((vars->name_length < OIDp[2].name_len) || (memcmp(OIDp[2].name, vars->name, (vars->name_length - 1) * sizeof(oid)))) {
#ifdef DEBUG
                    fprintf(stderr, "reached end of interfaces\n");
#endif
                    lastifflag++;
                    break;
                }

                /* now we fill our interfaces array with the index number and
                 * the description that we have received
                 */
                if (vars->type == ASN_OCTET_STR) {
                    if (config.trimdescr && config.trimdescr < vars->val_len) {
                        interfaces[count].index = (int) vars->name[(vars->name_length - 1)];
                        MEMCPY(interfaces[count].descr, (vars->val.string)+config.trimdescr, vars->val_len - config.trimdescr);
                        TERMSTR(interfaces[count].descr, vars->val_len - config.trimdescr);
                    } else {
                        interfaces[count].index = (int) vars->name[(vars->name_length - 1)];
                        MEMCPY(interfaces[count].descr, vars->val.string, vars->val_len);
                        TERMSTR(interfaces[count].descr, vars->val_len);
                    }
                    count++;
                }
            }

            if (count < ifNumber) {
                if (lastifflag)
                {
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
                lastifflag++;
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

            if (status == STAT_SUCCESS)
                printf("Error in packet\nReason: %s\n",
                        snmp_errstring(response->errstat));
            else if (status == STAT_TIMEOUT) {
                printf("Timeout while reading interface descriptions from %s\n",
                        session.peername);
                exit(EXITCODE_TIMEOUT);
            }
            else if (status == STAT_ERROR && ss->s_snmp_errno == SNMPERR_TIMEOUT) {
               printf("Timeout\n");
                exit(EXITCODE_TIMEOUT);
            } else
                snmp_sess_perror("snmp_bulkget", ss);
            exit (2);

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
     * this allows us later to only request the interface counters of the desired interfaces.
     */

    if (config.match_aliases_flag && config.list) {
        lastifflag = 0;
        count = 0;
        /* allocate the space for the alias OIDs */
        OIDp = (struct OIDStruct *) calloc(1, sizeof(struct OIDStruct));
        while (lastifflag==0) {

            /* build our request depending on the mode */
            if (count==0)
                create_pdu(config.mode, oid_aliasp, &pdu, &OIDp, 0, ifNumber);
            else {
                /* we have not received all aliases in the preceding packet, so fetch the next lot */

                if (config.mode == BINTEC || config.mode == NONBULK)
                    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
                else {
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
            status = snmp_synch_response(ss, pdu, &response);
#ifdef DEBUG
            benchmark_end();
            free(implode_result);
#endif
            if (config.sleep_usecs) usleep(config.sleep_usecs);

            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

                vars = response->variables;

                for (vars = vars; vars; vars = vars->next_variable) {
                    /*
                     * if the next OID is shorter
                     * or if the next OID doesn't begin with our base OID
                     * then we have reached the end of the table :-)
                     * print_variable(vars->name, vars->name_length, vars);
                     */

                    /* save the OID in case we need additional packets */
                    memcpy(lastOid.name, vars->name, (vars->name_length  * sizeof(oid)));
                    lastOid.name_len = vars->name_length;

                    if ((vars->name_length < OIDp[0].name_len) || (memcmp(OIDp[0].name, vars->name, (vars->name_length - 1) * sizeof(oid)))) {
#ifdef DEBUG
                        fprintf(stderr, "reached end of aliases\n");
#endif
                        lastifflag++;
                        break;
                    }

                    /* now we fill our interfaces array with the alias
                     */
                    if (vars->type == ASN_OCTET_STR) {
                        int i = (int) vars->name[(vars->name_length - 1)];
                        if (i)  {
                            MEMCPY(interfaces[count].alias, vars->val.string, vars->val_len);
                            TERMSTR(interfaces[count].alias, vars->val_len);
                        }
                    }
                    count++;
                }

                if (count < ifNumber) {
                    if (lastifflag) {
#ifdef DEBUG
                        fprintf(stderr, "Device has %d interfaces but only has %d aliases\n", ifNumber, count);
#endif
                    } else {
#ifdef DEBUG
                        fprintf(stderr, "Sending another packet for aliases\n");
#endif
                    }
                } else
                    lastifflag++;
            } else {
                /*
                 * FAILURE: print what went wrong!
                 */

                if (status == STAT_SUCCESS)
                    printf("Error in packet\nReason: %s\n",
                            snmp_errstring(response->errstat));
                else if (status == STAT_TIMEOUT) {
                    printf("Timeout while reading interface aliases from %s\n",
                            session.peername);
                    exit(EXITCODE_TIMEOUT);
                } else
                    snmp_sess_perror("snmp_bulkget", ss);
                exit (2);
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
    }

    /* If the get_names_flag is set, we also have to get the interface names so we can match the regex with them */

    /* TODO: This is just a slightly changed copy from above. I think it could be solved better (i.e. by putting it into a function) but it works this way :-) */

    if (config.get_names_flag && config.list) {
        lastifflag = 0;
        count = 0;
        /* allocate the space for the names OIDs */
        OIDp = (struct OIDStruct *) calloc(1, sizeof(struct OIDStruct));
        while (lastifflag==0) {

            /* build our request depending on the mode */
            if (count==0)
                create_pdu(config.mode, oid_namesp, &pdu, &OIDp, 0, ifNumber);
            else {
                /* we have not received all names in the preceding packet, so fetch the next lot */

                if (config.mode == BINTEC || config.mode == NONBULK)
                    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
                else {
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
            status = snmp_synch_response(ss, pdu, &response);
#ifdef DEBUG
            benchmark_end();
            free(implode_result);
#endif
            if (config.sleep_usecs) usleep(config.sleep_usecs);

            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

                vars = response->variables;

                for (vars = vars; vars; vars = vars->next_variable) {
                    /*
                     * if the next OID is shorter
                     * or if the next OID doesn't begin with our base OID
                     * then we have reached the end of the table :-)
                     * print_variable(vars->name, vars->name_length, vars);
                     */

                    /* save the OID in case we need additional packets */
                    memcpy(lastOid.name, vars->name, (vars->name_length  * sizeof(oid)));
                    lastOid.name_len = vars->name_length;

                    if ((vars->name_length < OIDp[0].name_len) || (memcmp(OIDp[0].name, vars->name, (vars->name_length - 1) * sizeof(oid)))) {
#ifdef DEBUG
                        fprintf(stderr, "reached end of names\n");
#endif
                        lastifflag++;
                        break;
                    }

                    /* now we fill our interfaces array with the names
                     */
                    if (vars->type == ASN_OCTET_STR) {
                        int i = (int) vars->name[(vars->name_length - 1)];
                        if (i)  {
                            MEMCPY(interfaces[count].name, vars->val.string, vars->val_len);
                            TERMSTR(interfaces[count].name, vars->val_len);
                        }
                    }
                    count++;
                }

                if (count < ifNumber) {
                    if (lastifflag) {
#ifdef DEBUG
                        fprintf(stderr, "Device has %d interfaces but only has %d names\n", ifNumber, count);
#endif
                    } else {
#ifdef DEBUG
                        fprintf(stderr, "Sending another packet for names\n");
#endif
                    }
                } else
                    lastifflag++;
            } else {
                /*
                 * FAILURE: print what went wrong!
                 */

                if (status == STAT_SUCCESS)
                    printf("Error in packet\nReason: %s\n",
                            snmp_errstring(response->errstat));
                else if (status == STAT_TIMEOUT) {
                    printf("Timeout while reading interface names from %s\n",
                            session.peername);
                    exit(EXITCODE_TIMEOUT);
                } else
                    snmp_sess_perror("snmp_bulkget", ss);
                exit (2);
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
    }

    if (config.list) {
        /*
         * a regex was given so we will go through our array
         * and try and match it with what we received
         *
         * count is the number of matches
         */

        count = 0;
        for (int i=0; i < ifNumber; i++) {
            /* When --if-name is set ignore descr in favor of name, else use old behaviour */
            if (config.get_names_flag)
                status =  !regexec(&config.re, interfaces[i].name, (size_t) 0, NULL, 0) ||
                           (config.match_aliases_flag && !(regexec(&config.re, interfaces[i].alias, (size_t) 0, NULL, 0)));
            else
                status =  !regexec(&config.re, interfaces[i].descr, (size_t) 0, NULL, 0) ||
                           (config.match_aliases_flag && !(regexec(&config.re, interfaces[i].alias, (size_t) 0, NULL, 0)));
            status2 = 0;
            if (status && config.exclude_list) {
                if (config.get_names_flag)
                    status2 = !regexec(&config.exclude_re, interfaces[i].name, (size_t) 0, NULL, 0) ||
                              (config.match_aliases_flag && !(regexec(&config.re, interfaces[i].alias, (size_t) 0, NULL, 0)));
                else
                    status2 = !regexec(&config.exclude_re, interfaces[i].descr, (size_t) 0, NULL, 0) ||
                              (config.match_aliases_flag && !(regexec(&config.exclude_re, interfaces[i].alias, (size_t) 0, NULL, 0)));
            } if (status && !status2) {
                count++;
#ifdef DEBUG
                fprintf(stderr, "Interface %d (%s) matched\n", interfaces[i].index, interfaces[i].descr);
#endif
            } else
                interfaces[i].ignore = 1;
        }
        regfree(&config.re);

      if (config.exclude_list)
          regfree(&config.exclude_re);

      if (count) {
#ifdef DEBUG
          fprintf(stderr, "- %d interface%s found\n", count, (count==1)?"":"s");
#endif
      } else {
          printf("- no interfaces matched regex");
          exit (0);
      }
    }


    /* now retrieve the interface values in 2 GET requests
     * N.B. if the interfaces are continuous we could try
     * a bulk get instead
     */
    for (j = 0; j < ifNumber; j++) {
        /* add the interface to the oldperfdata list */
        strcpy_nospaces(oldperfdata[j].descr, interfaces[j].descr);

        if (!interfaces[j].ignore) {

            /* fetch the standard values first */
            if (create_request(ss, &OIDp, oid_vals, interfaces[j].index, &response, config.sleep_usecs)) {
                for (vars = response->variables; vars; vars = vars->next_variable) {
                    k = -1;
                    /* compare the received value to the requested value */
                    for ( int i = 0; oid_vals[i]; i++) {
                        if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len*sizeof(oid))) {
                            k = i;
                            break;
                        }
                    }

                    switch(k) /* the offset into oid_vals */
                    {
                        case 0: /* ifAdminStatus */
                            if (vars->type == ASN_INTEGER && *(vars->val.integer)==2) {
                                /* ignore interfaces that are administratively down */
                                interfaces[j].admin_down= 1;
                                ignore_count++;
                            }
                            break;
                        case 1: /*ifOperStatus */
                            if (vars->type == ASN_INTEGER)
                                /* 1 is up(OK), 3 is testing (assume OK), 5 is dormant(assume OK) */
                                interfaces[j].status = (*(vars->val.integer)==1 || *(vars->val.integer)==5 || *(vars->val.integer)==3)?1:0;
                            break;
                        case 2: /* ifInOctets */
                            if (vars->type == ASN_COUNTER)
                                interfaces[j].inOctets = *(vars->val.integer);
                            break;
                        case 3: /* ifInDiscards */
                            if (vars->type == ASN_COUNTER)
                                interfaces[j].inDiscards = *(vars->val.integer);
                            break;
                        case 4: /* ifInErrors or locIfInCRC */
                            if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER)
                                interfaces[j].inErrors = *(vars->val.integer);
                            break;
                        case 5: /* ifOutOctets */
                            if (vars->type == ASN_COUNTER)
                                interfaces[j].outOctets = *(vars->val.integer);
                            break;
                        case 6: /* ifOutDiscards */
                            if (vars->type == ASN_COUNTER)
                                interfaces[j].outDiscards = *(vars->val.integer);
                            break;
                        case 7: /* ifOutErrors or locIfCollisions */
                            if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER)
                                interfaces[j].outErrors = *(vars->val.integer);
                            break;
                    }
                }
                if (response) {
                    snmp_free_pdu(response);
                    response = 0;
                }


            }

            /* now fetch the extended oids (64 bit counters etc.) */
            if (create_request(ss, &OIDp, oid_extended, interfaces[j].index, &response, config.sleep_usecs)) {
                for (vars = response->variables; vars; vars = vars->next_variable) {
                    k = -1;
                    /* compare the received value to the requested value */
                    for ( int i = 0; oid_extended[i]; i++) {
                        if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len*sizeof(oid))) {
                            k = i;
                            break;
                        }
                    }


                    switch(k) /* the offset into oid_extended */
                    {
                        case 0: /* ifHCInOctets */
                            if (vars->type == ASN_COUNTER64)
                                interfaces[j].inOctets = convertto64((vars->val.counter64), 0);
                            break;
                        case 1: /* ifHCOutOctets */
                            if (vars->type == ASN_COUNTER64)
                                interfaces[j].outOctets = convertto64((vars->val.counter64), 0);
                            break;
                        case 2: /* ifInUcastPkts */
                            if (vars->type == ASN_COUNTER)
                                interfaces[j].inUcast = *(vars->val.integer);
                            break;
                        case 3: /* ifOutUcastPkts */
                            if (vars->type == ASN_COUNTER)
                                interfaces[j].outUcast = *(vars->val.integer);
                            break;
                        case 4: /* ifSpeed */
                            /* don't overwrite a high-speed value */
                            if (vars->type == ASN_GAUGE && !(interfaces[j].speed))
                                interfaces[j].speed = *(vars->val.integer);
                            break;
                        case 5: /* ifHighSpeed */
                            if (vars->type == ASN_GAUGE)
                                /* convert to bits / sec */
                                interfaces[j].speed = ((u64)*(vars->val.integer)) * 1000000ULL;
                            break;
                        case 6: /* alias */
                            if (vars->type == ASN_OCTET_STR)
                                MEMCPY(interfaces[j].alias, vars->val.string, vars->val_len);
                            break;
                        case 7: /* name */
                            if (vars->type == ASN_OCTET_STR)
                                MEMCPY(interfaces[j].name, vars->val.string, vars->val_len);
                            break;
                    }

                }
                if (response) {
                    snmp_free_pdu(response);
                    response = 0;
                }
            }

            /* now fetch the Cisco-specific extended oids */
            if (config.mode == CISCO && create_request(ss, &OIDp, oid_extended_cisco, interfaces[j].index, &response, config.sleep_usecs)) {
                for (vars = response->variables; vars; vars = vars->next_variable) {
                    k = -1;
                    /* compare the received value to the requested value */
                    for ( int i = 0; oid_extended_cisco[i]; i++) {
                        if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len*sizeof(oid))) {
                            k = i;
                            break;
                        }
                    }

                    switch(k) /* the offset into oid_extended_cisco */
                    {
                        case 0: /* portAdditionalOperStatus */
                            if (vars->type == ASN_OCTET_STR)
                                interfaces[j].err_disable = !!(vars->val.string[1] & (unsigned char)32u);
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


    /* let the user know about interfaces that are down (and subsequently ignored) */
    if (ignore_count)
        addstr(&out, " - %d %s administratively down", ignore_count, ignore_count!=1?"are":"is");

    if (OIDp) {
        free(OIDp);
        OIDp = 0;
    }


    /* calculate time taken, print perfdata */

    gettimeofday(&tv, &tz);

    if (config.oldperfdatap && config.oldperfdatap[0])
        parse_perfdata(config.oldperfdatap, oldperfdata, config.prefix, &parsed_lastcheck, config.mode);

    if (config.lastcheck) config.lastcheck=(starttime - config.lastcheck);
    else if (parsed_lastcheck) config.lastcheck=(starttime - parsed_lastcheck);

    /* do not use old perfdata if the device has been reset recently
     * Note that a switch will typically rollover the uptime counter every 497 days
     * which is infrequent enough to not bother about :-)
     * UPTIME_TOLERANCE_IN_SECS doesn't need to be a big number
     */
    if ((config.lastcheck + UPTIME_TOLERANCE_IN_SECS) > uptime)
        config.lastcheck = 0;

    for (int i=0;i<ifNumber;i++)  {
        if (!interfaces[i].ignore) {
            int warn = 0;

            char *nameOrDescr = config.get_names_flag && strlen(interfaces[i].name)
                ? interfaces[i].name : interfaces[i].descr;

            if ((!interfaces[i].status || interfaces[i].err_disable) && !interfaces[i].ignore && !interfaces[i].admin_down) {
                if (config.crit_on_down_flag) {
                    addstr(&perf, "[CRITICAL] ");
                    errorflag++;
                    /* show the alias if configured */
                    if (config.get_names_flag && strlen(interfaces[i].name)) {
                        addstr(&out, ", %s", interfaces[i].name);
                        addstr(&perf, "%s", interfaces[i].name);
                    } else {
                        addstr(&out, ", %s", interfaces[i].descr);
                        addstr(&perf, "%s", interfaces[i].descr);
                    }
                    if (!interfaces[i].admin_down) {
                        if (config.get_aliases_flag && strlen(interfaces[i].alias)) {
                            addstr(&out, " (%s) down", interfaces[i].alias);
                            addstr(&perf, " (%s) down", interfaces[i].alias);
                        } else {
                            addstr(&out, " down");
                            addstr(&perf, " down");
                        }
                        if (interfaces[i].err_disable) {
                            addstr(&out, " (errdisable)");
                            addstr(&perf, " (errdisable)");
                        }
                    }
                } else {
                    addstr(&perf, "[OK] ");
                    if (config.get_names_flag && strlen(interfaces[i].name))
                        addstr(&perf, "%s", interfaces[i].name);
                    else
                        addstr(&perf, "%s", interfaces[i].descr);
                    if (config.get_aliases_flag && strlen(interfaces[i].alias))
                        addstr(&perf, " (%s) down", interfaces[i].alias);
                    else
                        addstr(&perf, " down");
                }
            } else if (interfaces[i].admin_down && config.print_all_flag) {
                addstr(&perf, "[OK] %s", (config.get_names_flag && strlen(interfaces[i].name)) ? interfaces[i].name : interfaces[i].descr);
                if (config.get_aliases_flag && strlen(interfaces[i].alias))
                    addstr(&perf, " (%s) is down (administrative down)", interfaces[i].alias);
                else
                    addstr(&perf, " is down (administrative down)");
            }


            /* check if errors on the interface are increasing faster than our defined value */
            else if ((oldperfdata[i].inErrors || oldperfdata[i].outErrors) &&
                (interfaces[i].inErrors > (oldperfdata[i].inErrors + (unsigned long) config.err_tolerance)
                || interfaces[i].outErrors > (oldperfdata[i].outErrors + (unsigned long) config.coll_tolerance))
                ) {
                if (config.oldperfdatap && !interfaces[i].ignore) {
                    if (config.get_names_flag && strlen(interfaces[i].name))
                        addstr(&perf, "[WARNING] %s", interfaces[i].name);
                    else
                        addstr(&perf, "[WARNING] %s", interfaces[i].descr);

                    if (config.get_aliases_flag && strlen(interfaces[i].alias))
                        addstr(&perf, " (%s) has", interfaces[i].alias);
                    else
                        addstr(&perf, " has");

                    /* if we are not in cisco mode simply use "errors" */

                    if (config.mode != CISCO)
                        addstr(&perf, " errors\n");
                    else {
                         if (interfaces[i].inErrors > (oldperfdata[i].inErrors + (unsigned long) config.err_tolerance))
                              addstr(&perf, " %lu CRC errors since last check\n", interfaces[i].inErrors - oldperfdata[i].inErrors);
                         if (interfaces[i].outErrors > (oldperfdata[i].outErrors + (unsigned long) config.coll_tolerance))
                              addstr(&perf, " %lu collisions since last check\n", interfaces[i].outErrors - oldperfdata[i].outErrors);
                    }
                    if (config.get_names_flag && strlen(interfaces[i].name))
                        addstr(&out, ", %s has %lu errors", interfaces[i].name,
                            (interfaces[i].inErrors + interfaces[i].outErrors - oldperfdata[i].inErrors - oldperfdata[i].outErrors));
                    else
                        addstr(&out, ", %s has %lu errors", interfaces[i].descr,
                            (interfaces[i].inErrors + interfaces[i].outErrors - oldperfdata[i].inErrors - oldperfdata[i].outErrors));
                    warnflag++;
                    //warn++; /* if you uncomment this you will get 2 rows with [warning] */
                }
            }

            if (config.lastcheck && (interfaces[i].speed || config.speed) && !interfaces[i].admin_down && (oldperfdata[i].inOctets || oldperfdata[i].outOctets)) {
                interfaces[i].inbitps = (subtract64(interfaces[i].inOctets, oldperfdata[i].inOctets, config.lastcheck) / (u64)config.lastcheck) * 8ULL;
                interfaces[i].outbitps = (subtract64(interfaces[i].outOctets, oldperfdata[i].outOctets, config.lastcheck) / (u64)config.lastcheck) * 8ULL;
                if (config.speed) {
                    inload = (long double)interfaces[i].inbitps / ((long double)config.speed/100L);
                    outload = (long double)interfaces[i].outbitps / ((long double)config.speed/100L);
                } else {
                    /* use the interface speed if a speed is not given */
                    inload = (long double)interfaces[i].inbitps / ((long double)interfaces[i].speed/100L);
                    outload = (long double)interfaces[i].outbitps / ((long double)interfaces[i].speed/100L);
                }

                if ( (config.bandwith > 0) && ((int)inload > config.bandwith || (int)outload > config.bandwith)) {
                    warn++;
                    warnflag++;
                }
            }

            if (interfaces[i].status && !interfaces[i].ignore) {
                if (!(warn))
                    addstr(&perf, "[OK]");
                else
                    addstr(&perf, "[WARNING]");

                addstr(&perf, " %s", nameOrDescr);
                if (config.get_aliases_flag && strlen(interfaces[i].alias))
                    addstr(&perf, " (%s)", interfaces[i].alias);
                addstr(&perf, " is up");
            }
            if (config.lastcheck && (interfaces[i].speed || config.speed) && (interfaces[i].inbitps > 0ULL || interfaces[i].outbitps > 0ULL) && !interfaces[i].admin_down) {
                gauge_to_si(interfaces[i].inbitps, &ins);
                gauge_to_si(interfaces[i].outbitps, &outs);

                addstr(&perf, "   %sbps(%0.2f%%)/%sbps(%0.2f%%)", ins, inload, outs, outload);
                free(ins);
                free(outs);
            }
            if (perf.len > 0u && perf.text[(perf.len - 1u)] != '\n') {
                addstr(&perf, "\n");
            }
        }
    }

    if (errorflag)
        printf("CRITICAL:");
    else if (warnflag)
        printf("WARNING:");
    else
        printf("OK:");

    printf(" %d interface%s found", ifNumber, (ifNumber==1)?"":"s");
    if(config.list) printf(", of which %d matched the regex", count);


    /* now print performance data */


    printf("%*s | interfaces::check_multi::plugins=%d time=%.2Lf checktime=%ld", (int)out.len, out.text, count, (((long double)tv.tv_sec + ((long double)tv.tv_usec/1000000)) - starttime ), tv.tv_sec);
    if (uptime)
            printf(" %sdevice::check_snmp::uptime=%us", config.prefix?config.prefix:"", uptime);

    for (int i=0;i<ifNumber;i++)  {
        if (!interfaces[i].ignore && (!interfaces[i].admin_down || config.print_all_flag)) {
            printf(" %s%s::check_snmp::", config.prefix?config.prefix:"", oldperfdata[i].descr);
            printf("%s=%lluc %s=%lluc", if_vars[0], interfaces[i].inOctets, if_vars[1], interfaces[i].outOctets);
            printf(" %s=%luc %s=%luc", if_vars[2], interfaces[i].inDiscards, if_vars[3], interfaces[i].outDiscards);
            printf(" %s=%luc %s=%luc", if_vars[4], interfaces[i].inErrors, if_vars[5], interfaces[i].outErrors);
            printf(" %s=%luc %s=%luc", if_vars[6], interfaces[i].inUcast, if_vars[7], interfaces[i].outUcast);
            if (config.speed)
                printf(" %s=%llu", if_vars[8], config.speed);
            else
                printf(" %s=%llu", if_vars[8], interfaces[i].speed);
            printf(" %s=%llub %s=%llub", if_vars[9], interfaces[i].inbitps, if_vars[10], interfaces[i].outbitps);
        }
    }
    printf("\n%*s", (int)perf.len, perf.text);

#ifdef DEBUG
    benchmark_start("Close SNMP session");
#endif
    snmp_close(ss);
#ifdef DEBUG
    benchmark_end();
#endif

    SOCK_CLEANUP;
    return ((errorflag)?2:((warnflag)?1:0));
}


void print64(struct counter64 *count64, unsigned long *count32)
{

    if (!(isZeroU64(count64))) {
        char buffer[I64CHARSZ+1];
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


u64 convertto64(struct counter64 *val64, unsigned long *val32)
{
    u64 temp64;

    if ((isZeroU64(val64)))
    {
        if (val32)
            temp64 = (u64)(*val32);
        else
            temp64 = 0;
    }
    else
        temp64 = ((u64)(val64->high) << 32) + val64->low;

    return (temp64);
}

u64 subtract64(u64 big64, u64 small64, unsigned int lastcheck)
{
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

netsnmp_session *start_session(netsnmp_session *session, char *community, char *hostname, enum mode_enum mode, unsigned long global_timeout, int session_retries)
{
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
    ss = snmp_open(session);    /* establish the session */

    if (!ss) {
        snmp_sess_perror("snmp_bulkget", session);
        SOCK_CLEANUP;
        exit(1);
    }

    return(ss);

}

netsnmp_session *start_session_v3(netsnmp_session *session, char *user, char *auth_proto, char *auth_pass, char *priv_proto, char *priv_pass, char *hostname, unsigned long global_timeout, int session_retries)
{
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
            session->securityPrivProto = snmp_duplicate_objid(usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
#ifdef usmDESPrivProtocol
        } else if (!strcmp(priv_proto, "DES")) {
            session->securityPrivProto = snmp_duplicate_objid(usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
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
            session->securityAuthProto = snmp_duplicate_objid(usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
            session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
        } else if (!strcmp(auth_proto, "MD5")) {
            session->securityAuthProto = snmp_duplicate_objid(usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
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

    if ((session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) || (session->securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV)) {
        if(generate_Ku(session->securityAuthProto, session->securityAuthProtoLen, (unsigned char *)auth_pass, strlen(auth_pass),
                    session->securityAuthKey, &session->securityAuthKeyLen) != SNMPERR_SUCCESS)
            printf("Error generating AUTH sess\n");
        if (session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
            if (generate_Ku(session->securityAuthProto, session->securityAuthProtoLen, (unsigned char *)priv_pass, strlen(priv_pass),
                        session->securityPrivKey, &session->securityPrivKeyLen) != SNMPERR_SUCCESS)
                printf("Error generating PRIV sess\n");
        }
    }

    session->timeout = global_timeout;
    session->retries = session_retries;

    /*
     * Open the session
     */
    SOCK_STARTUP;
    ss = snmp_open(session);    /* establish the session */

    if (!ss) {
        snmp_sess_perror("snmp_bulkget", session);
        SOCK_CLEANUP;
        exit(1);
    }

    return(ss);

}


int usage(char *progname)
{
    int i;
    printf(
#ifdef PACKAGE_STRING
    PACKAGE_STRING "\n\n"
#endif
    "Usage: %s -h <hostname> [OPTIONS]\n", progname);

    printf(" -c|--community\t\tcommunity (default public)\n");
    printf(" -r|--regex\t\tinterface list regexp\n");
    printf(" -R|--exclude-regex\tinterface list negative regexp\n");
    printf(" -e|--errors\t\tnumber of in errors (CRC errors for cisco) to consider a warning (default 50)\n");
    printf(" -f|--out-errors\tnumber of out errors (collisions for cisco) to consider a warning (default same as in errors)\n");
    printf(" -p|--perfdata\t\tlast check perfdata\n");
    printf(" -P|--prefix\t\tprefix interface names with this label\n");
    printf(" -t|--lastcheck\t\tlast checktime (unixtime)\n");
    printf(" -b|--bandwidth\t\tbandwidth warn level in %%\n");
    printf(" -s|--speed\t\toverride speed detection with this value (bits per sec)\n");
    printf(" -x|--trim\t\tcut this number of characters from the start of interface descriptions\n");
    printf(" -m|--mode\t\tspecial operating mode (");
    for (i=0; modes[i]; i++) {
        printf("%s%s", i?",":"", modes[i]);
    }
    printf(")\n");
    printf(" -j|--auth-proto\tSNMPv3 Auth Protocol (SHA|MD5)\n");
    printf(" -J|--auth-phrase\tSNMPv3 Auth Phrase\n");
#ifdef usmDESPrivProtocol
    printf(" -k|--priv-proto\tSNMPv3 Privacy Protocol (AES|DES), unset means not privacy protocol!\n");
#else
    printf(" -k|--priv-proto\tSNMPv3 Privacy Protocol (AES), unset means not privacy protocol!\n");
#endif
    printf(" -K|--priv-phrase\tSNMPv3 Privacy Phrase\n");
    printf(" -u|--user\t\tSNMPv3 User\n");
    printf(" -d|--down-is-ok\tdisables critical alerts for down interfaces\n");
    printf(" -a|--aliases\t\tretrieves the interface description\n");
    printf(" -A|--match-aliases\talso match against aliases (Option -a automatically enabled)\n");
    printf(" -D|--debug-print\tlist administrative down interfaces in perfdata\n");
    printf(" -N|--if-names\t\tuse ifName instead of ifDescr\n");
    printf("    --timeout\t\tsets the SNMP timeout (in ms)\n");
    printf("    --sleep\t\tsleep between every SNMP query (in ms)\n");
    printf("    --retries\t\thow often to retry before giving up\n");
    printf("    --max-repetitions\t\tsee <http://www.net-snmp.org/docs/man/snmpbulkwalk.html>\n");
    printf("\n");
    return 3;
}

/*
 * tokenize a string containing performance data and fill a struct with
 * the individual variables
 *
 * e.g.  interfaces::check_multi::plugins=2 time=0.07 11::check_snmp::inOctets=53273084427c outOctets=6370502528c inDiscards=0c outDiscards=3921c inErrors=3c outErrors=20165c inUcast=38550136c outUcast=21655535c speed=100000000 21::check_snmp::inOctets=5627677780c outOctets=15023959911c inDiscards=0c outDiscards=0c inErrors=0c outErrors=5431c inUcast=34020897c outUcast=35875426c speed=1000000000
 */
int parse_perfdata(char *oldperfdatap, struct ifStruct *oldperfdata, char *prefix, unsigned int *parsed_lastcheck, enum mode_enum mode)
{
    char *last=0, *last2=0, *word, *interface=0, *var;
    char *ptr;
#ifdef DEBUG
    int plugins;
    int uptime_old;
#endif
    u64 value=0;
    char *valstr;



    /* first split at spaces */
    for ( word = strtok_r(oldperfdatap, " ", &last); word; word = strtok_r(NULL, " ", &last)) {
        if((ptr = strstr(word, "::check_multi::plugins="))) {
#ifdef DEBUG
            /* check multi perfdata found */
            plugins = strtol(strchr(word, '=') + 1, NULL, 10);
            fprintf(stderr, "Found %d plugins\n", plugins);
#endif
            continue;
        }

        if((ptr = strstr(word, "checktime="))) {
            /* last checktime found */
            *parsed_lastcheck = strtol(strchr(word, '=') + 1, NULL, 10);
#ifdef DEBUG
            fprintf(stderr, "Found last checktime: %d\n", *parsed_lastcheck);
#endif
            continue;
        }

        if((ptr = strstr(word, "device::check_snmp::"))) {
#ifdef DEBUG
            /* uptime found */
            uptime_old = strtol(strchr(word, '=') + 1, NULL, 10);
            fprintf(stderr, "Found %u uptime\n", uptime_old);
#endif
            continue;
        }

        if((ptr = strstr(word, "::check_snmp::"))) {
            /* new interface found, get its name (be aware that this is the "cleaned" string */
            interface = strtok_r(word, ":", &last2);

            /* remove any prefix */
            if (prefix) {
                if (strlen(interface)>strlen(prefix))
                    interface = interface + strlen(prefix);
            }
#ifdef DEBUG
           if (interface)
                fprintf(stderr, "interface %s found\n", interface);
#endif
           word  = (ptr + strlen("::check_snmp::"));
        }

        /* finally split the name=value pair */
        valstr = strchr(word, '=');
        if (valstr)
            value = strtoull(valstr + 1, NULL, 10);

        var = strtok_r(word, "=", &last2);

        if (interface && var && valstr)
            set_value(oldperfdata, interface, var, value, valstr + 1, mode);

    }


    return (0);
}


/*
 * fill the ifStruct with values
 */
void set_value(struct ifStruct *oldperfdata, char *interface, char *var, u64 value, char *valstr, enum mode_enum mode)
{
    int i;
    static char **if_vars;

    if (mode == CISCO)
        if_vars = if_vars_cisco;
    else
        if_vars = if_vars_default;

    for (i=0; i < ifNumber; i++) {
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
int create_request(netsnmp_session *ss, struct OIDStruct **OIDpp, char **oid_list, int index, netsnmp_pdu **response, unsigned int sleep_usecs)
{
    netsnmp_pdu     *pdu;
    int         status, i;
    struct OIDStruct    *OIDp;

    /* store all the parsed OIDs in a structure for easy comparison */
    for (i = 0; oid_list[i]; i++);
    OIDp = (struct OIDStruct *) calloc(i, sizeof(*OIDp));

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
    if (sleep_usecs) usleep(sleep_usecs);

    if (status == STAT_SUCCESS && (*response)->errstat == SNMP_ERR_NOERROR) {
        return(1);
    }
    else if (status == STAT_SUCCESS && (*response)->errstat == SNMP_ERR_NOSUCHNAME) {
        /* if e.g. 64 bit counters are not supported, we will get this error */
        return(1);
    } else {
        /*
         * FAILURE: print what went wrong!
         */

        if (status == STAT_SUCCESS)
            printf("Error in packet\nReason: %s\n",
                snmp_errstring((*response)->errstat));
        else if (status == STAT_TIMEOUT)
        {
            printf("Timeout fetching interface stats from %s ",
                ss->peername);
            for (i = 0; oid_list[i]; i++) {
                printf("%c%s", i?',':'(', oid_list[i]);
            }
            printf(")\n");
            exit(EXITCODE_TIMEOUT);
        }
        else {
            printf("other error\n");
            snmp_sess_perror("snmp_bulkget", ss);
        }
    exit(2);
    }

    return(0);
}


int parseoids(int i, char *oid_list, struct OIDStruct *query)
{
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
    return(0);
}

void create_pdu(int mode, char **oidlist, netsnmp_pdu **pdu, struct OIDStruct **oids, int nonrepeaters, long max)
{
    int i;

    if (mode == NONBULK)
        *pdu = snmp_pdu_create(SNMP_MSG_GET);

    else if (mode == BINTEC) {
        /* we cannot use a bulk get for bintec
         * and the oids don't increment properly
         */
        *pdu = snmp_pdu_create(SNMP_MSG_GET);
    }
    else {
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

void parse_and_check_commandline(int argc, char **argv, struct configuration_struct *config) {
    int opt;

    char *progname = strrchr(argv[0], '/');
    if (*progname && *(progname+1))
        progname++;
    else
        progname = "check_interfaces";

    /* parse options */
    static struct option longopts[] =
    {
        {"aliases",     no_argument,        NULL,   'a'},
        {"match-aliases",     no_argument,  NULL,   'A'},
        {"bandwidth",   required_argument,  NULL,   'b'},
        {"community",   required_argument,  NULL,   'c'},
        {"down-is-ok",  no_argument,        NULL,   'd'},
        {"errors",      required_argument,  NULL,   'e'},
        {"out-errors",  required_argument,  NULL,   'f'},
        {"hostname",    required_argument,  NULL,   'h'},
        {"auth-proto",  required_argument,  NULL,   'j'},
        {"auth-phrase", required_argument,  NULL,   'J'},
        {"priv-proto",  required_argument,  NULL,   'k'},
        {"priv-phrase", required_argument,  NULL,   'K'},
        {"mode",        required_argument,  NULL,   'm'},
        {"perfdata",    required_argument,  NULL,   'p'},
        {"prefix",      required_argument,  NULL,   'P'},
        {"regex",       required_argument,  NULL,   'r'},
        {"exclude-regex",    required_argument,    NULL,    'R'},
        {"if-names",    no_argument,        NULL,   'N'},
        {"debug-print", no_argument,        NULL,   'D'},
        {"speed",       required_argument,  NULL,   's'},
        {"lastcheck",   required_argument,  NULL,   't'},
        {"user",        required_argument,  NULL,   'u'},
        {"trim",        required_argument,  NULL,   'x'},
        {"help",        no_argument,        NULL,   '?'},
        {"timeout",     required_argument,  NULL,   2},
        {"sleep",       required_argument,  NULL,   3},
        {"retries",     required_argument,  NULL,   4},
        {"max-repetitions", required_argument, NULL, 5},
        {NULL,          0,                  NULL,   0}
    };


    while ((opt = getopt_long(argc, argv, "aAb:c:dDe:f:h:j:J:k:K:m:Np:P:r:R:s:t:u:x:?", longopts, NULL)) != -1)
    {
        switch(opt)
        {
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
                for (int i=0; modes[i]; i++)
                {
                    if (!strcmp(optarg, modes[i]))
                    {
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
                config->list = optarg;
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
            case '?':
            default:
                exit(usage(progname));

        }
    }
    argc -= optind;
    argv += optind;

    if (config->coll_tolerance == -1)
    {
        /* set the outErrors tolerance to that of inErrors unless explicitly set otherwise */
        config->coll_tolerance = config->err_tolerance;
    }

    if (!(config->hostname))
    {
        exit(usage(progname));
    }

#ifdef HAVE_GETADDRINFO
    struct addrinfo *addr_list;
    /* check for a valid hostname / IP Address */
    if(getaddrinfo(config->hostname, NULL, NULL, &addr_list)) {
        printf("Failed to resolve hostname %s\n", config->hostname);
        exit(3);
    }
    /* name is resolvable - pass it to the snmplib */
    freeaddrinfo(addr_list);
#endif /* HAVE_GETADDRINFO */

    if (!config->community)
        config->community = default_community;

    if (config->exclude_list && !config->list)
        /* use .* as the default regex */
        config->list = ".*";

    /* get the start time */

    /* parse the interfaces regex */
    int status;
    if (config->list) {
        status = regcomp(&config->re, config->list, REG_ICASE|REG_EXTENDED|REG_NOSUB);
        if (status != 0) {
            printf("Error creating regex\n");
            exit (3);
        }

        if (config->exclude_list) {
            status = regcomp(&config->exclude_re, config->exclude_list, REG_ICASE|REG_EXTENDED|REG_NOSUB);
            if (status != 0) {
                printf("Error creating exclusion regex\n");
                exit (3);
            }
        }
    }

    /* set the MIB variable if it is unset to avoid net-snmp warnings */
    if (getenv("MIBS") == NULL)
        setenv("MIBS", "", 1);
}
