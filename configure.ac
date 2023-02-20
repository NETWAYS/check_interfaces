AC_INIT([check_interfaces],[1.4])
AC_PREFIX_DEFAULT(/usr/local/nagios)
AC_PROG_CC
AC_PROG_INSTALL


if test "$cross_compiling" != "yes";
then
    dnl look for net-snmp-config
    AC_PATH_PROG(NETSNMPCONFIG, net-snmp-config)

    if test "$ac_cv_path_netsnmpconfig" == "no";
    then
        AC_MSG_WARN([could not find net-snmp-config - did you install the development package for net-snmp?  ])
    else
        SNMP_CFLAGS=`$NETSNMPCONFIG --cflags`
        SNMP_LIBS=`$NETSNMPCONFIG --libs`
        CFLAGS="$CFLAGS $SNMP_CFLAGS"
    fi
fi

AC_ARG_WITH(snmp-headers,
   AS_HELP_STRING([--with-snmp-headers=DIR], [Net-SNMP Include files location]),
   [SNMP_HDR_DIR="$withval"]
   [CPPFLAGS="$CPPFLAGS -I$withval"])

dnl if specified override SNMP_LIBS
AC_ARG_WITH(snmp-libs,
  AS_HELP_STRING([--with-snmp-libs=DIR], [Net-SNMP Shared Library files location]),
  [SNMP_LIBS="-lnetsnmp"]
  [CFLAGS="$CFLAGS -L$withval"])


AC_CHECK_HEADERS([net-snmp/net-snmp-config.h])

AC_CHECK_LIB(netsnmp, snmp_open)

if test "$ac_cv_header_net_snmp_net_snmp_config_h" != "yes";
then
    AC_MSG_ERROR([Net-SNMP Headers Missing])
fi

if test "$ac_cv_lib_netsnmp_snmp_open" != "yes";
then
    AC_MSG_ERROR([Net-SNMP library unusable - either it is missing or there are unfulfilled dependencies (e.g. libcrypto)])
fi


dnl look for the pow() function
AC_SEARCH_LIBS(pow, [c m], AC_DEFINE([HAVE_POW]))

dnl look for the getaddrinfo() function
AC_SEARCH_LIBS(getaddrinfo, [c], AC_DEFINE([HAVE_GETADDRINFO]))


AC_SUBST([SNMP_LIBS])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
