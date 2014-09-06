check_interfaces
================

This plugin uses the bulk-get mode of SNMPv2 by default - pass it the option -m NONBULK to work with SNMPv1. Support for SNMPv3 with and without privacy is included.

64 bit counters will be used if they are supported by the device.


### Installation

In order to compile this plugin you will need the `NET SNMP Development` package
(libsnmp-dev under Debian) as well as `autoconf` and the standard compilation tools.

    autoconf (only needed if the configure script has not been created)
    ./configure

Running "make" should successfully compile the plugin, and "make install" will install them under
the configured path.

    make 
    make install


### Usage


(see also check_interface --help)

    check_interface -c public -h 192.168.0.1 -r 'FastEth' -p '$SERVICEPERFDATA$' -t $LASTSERVICECHECK$ -a
    
    Options;
     -h                 address of device
    
     -c|--community     community (default public)
     -r|--regex         interface list regexp
                            Regex to match interfaces (important, this is a Regular Expression
                            not a simple wildcard string, see below)
     -e|--errors        number of in errors (CRC errors for cisco) to consider a warning (default 50)
                            Only warn if errors increase by more than this amount between checks
     -f|--out-errors    number of out errors (collisions for cisco) to consider a warning
                            Defaults to the same value as for errors
     -p|--perfdata      last check perfdata
                            Performance data from previous check (used to calculate traffic)
     -P|--prefix        prefix interface names with this label
     -t|--lastcheck     last checktime (unixtime)
                            Last service check time in unixtime (also used to calculate traffic)
     -b|--bandwidth     bandwidth warn level in %
     -s|--speed         override speed detection with this value (bits per sec)
     -x|--trim          cut this number of characters from the start of interface descriptions
                            Useful for nortel switches
     -j|--auth-proto    SNMPv3 Auth Protocol (SHA|MD5)
     -J|--auth-phrase   SNMPv3 Auth Phrase
     -k|--priv-proto    SNMPv3 Privacy Protocol (AES|DES) (optional)
     -K|--priv-phrase   SNMPv3 Privacy Phrase
     -u|--user          SNMPv3 User
     -d|--down-is-ok    disables critical alerts for down interfaces
                            i.e do not consider a down interface to be critical
     -a|--aliases       retrieves the interface description
                            This alias does not always deliver useful information
     -A|--match-aliases also test the Alias against the Regexes
        --timeout       sets the SNMP timeout (in ms)
     -m|--mode          special operating mode (default,cisco,nonbulk,bintec)
                            Workarounds for various hardware


### Modes

     default    use SNMPv2 bulk-gets to retrieve the interface list (recommended for devices with many interfaces)
     cisco      retrieve CRC errors and collisions instead of in errors and out errors
     bintec     work with non-RFC Bintec devices
     nonbulk    use a traditional tree-walk and SNMPv1 instead of bulk-gets (less efficient, but works with most devices)


### Counter Overflows

The plugin will query the uptime of the device and compensate for counter overflows.
Note however that a 1Gbit interface with a 32 bit counter will overflow every 34 seconds
if the interface is operating at full capacity - in this case you will need to query the
device at least once a minute.  With 64 bit counters these problems go away.

Also be aware that the counter values themselves are passed unaltered in the performance
data field - if you graph the data then the grapher also needs to be overflow aware.


### Large Plugin Output


Be aware that this plugin may generate large outputs.  Your version of Nagios / Icinga may cut off the output and cause you problems with various graphing tools; for best results restrict the list of interfaces using the -r option

### Regular Expressions

The following patterns can be used to match strings

     .          anything
     ^          beginning of string
     $          end of string (WARNING: you need to use $$ in a Nagios configuration file!)
     (abc|def)  either abc or def
     [0-9a-z]   a range
     *          the previous pattern multiple times


Examples;

     Eth        match any strings containing "Eth"
     ^FastEth   match any strings beginning with "FastEth"
     Eth(0|2)$  match Eth0 or Eth2
     Eth(0|2)   as above but would also match Eth20, Eth21, Eth22 etc

If unsure of a pattern, you should test it on the command line thus;

    check_interface -c public -h 192.168.0.1 -r 'Eth(0|2)$'
