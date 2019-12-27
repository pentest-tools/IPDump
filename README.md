# IPDump
## A python utility for quickly generating reports for IP Addresses, Websites and domains.

Current features:
- Geolocation Information
- WHOIS Information
- Portscanning

I'm open to new features, please feel free to email me: adambruce0108@gmail.com.

## Usage
```
./ipdump.py -h
usage: ipdump.py [-h] [-l] [-c] [-a] [-p] [-i] [-w] [-n WORKERS] host

positional arguments:
  host                  The hostname/IP Address, URL or Domain of the target

optional arguments:
  -h, --help            show this help message and exit
  -l, --no-logging      Disable logging
  -c, --no-color        Disable colored logging
  -a, --all             Run all tools on the given target
  -p, --port-scan       Enable portscanning on the target
  -i, --ip-info         Fetch information from api-ip.com (contains
                        geographical info)
  -w, --whois           Fetch whois information from arin.net (contains domain
                        ownership info)
  -n WORKERS, --workers WORKERS
                        Number of workers for portscanning
```

## Examples: 

Getting IP Geolocation Information
```
./ipdump.py 91.7.125.52 -i 
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Requesting information from http://ip-api.com/json/
[+] Response from http://ip-api.com/json/:
status       : success
continent    : Europe
continentCode: EU
country      : Germany
countryCode  : DE
region       : NW
regionName   : North Rhine-Westphalia
city         : Kempen
district     : 
zip          : 47906
lat          : 51.3643
lon          : 6.4186
timezone     : Europe/Berlin
currency     : EUR
isp          : Deutsche Telekom AG
org          : Deutsche Telekom AG
as           : AS3320 Deutsche Telekom AG
asname       : DTAG
reverse      : p5B077D34.dip0.t-ipconnect.de
mobile       : False
proxy        : False
query        : 91.7.125.52
[+] Report for 91.7.125.52 completed

```

### Getting Website WHOIS Information
```
./ipdump.py github.com -w
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Sending whois query to whois.arin.net
[+] Response from whois.arin.net:

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2019, American Registry for Internet Numbers, Ltd.
#


#
# Query terms are ambiguous.  The query is assumed to be:
#     "n 140.82.118.3"
#
# Use "?" to get help.
#

NetRange:       140.82.112.0 - 140.82.127.255
CIDR:           140.82.112.0/20
NetName:        GITHU
NetHandle:      NET-140-82-112-0-1
Parent:         NET140 (NET-140-0-0-0-0)
NetType:        Direct Assignment
OriginAS:       AS36459
Organization:   GitHub, Inc. (GITHU)
RegDate:        2018-04-25
Updated:        2019-06-20
Ref:            https://rdap.arin.net/registry/ip/140.82.112.0


OrgName:        GitHub, Inc.
OrgId:          GITHU
Address:        88 Colin P Kelly Jr Street
City:           San Francisco
StateProv:      CA
PostalCode:     94107
Country:        US
RegDate:        2012-10-22
Updated:        2014-04-26
Comment:        https://github.com
Comment:        Please contact us directly for matters pertaining to abuse.
Comment:        Urgent matters including DDoS are handled 24x7.
Ref:            https://rdap.arin.net/registry/entity/GITHU


OrgAbuseHandle: GITHU1-ARIN
OrgAbuseName:   GitHub Abuse
OrgAbusePhone:  +1-415-857-5430 
OrgAbuseEmail:  abuse@github.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/GITHU1-ARIN

OrgNOCHandle: GITHU-ARIN
OrgNOCName:   GitHub Ops
OrgNOCPhone:  +1-415-735-4488 
OrgNOCEmail:  hostmaster@github.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/GITHU-ARIN

OrgTechHandle: GITHU-ARIN
OrgTechName:   GitHub Ops
OrgTechPhone:  +1-415-735-4488 
OrgTechEmail:  hostmaster@github.com
OrgTechRef:    https://rdap.arin.net/registry/entity/GITHU-ARIN


#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2019, American Registry for Internet Numbers, Ltd.
#


[+] Report for github.com completed
```

### Example: Portscanning a Server
```
./ipdump.py imap.gmail.com -p
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Portscanning imap.gmail.com for open ports in the range 1-1024
+-------+------------------------------+-----------+--------------------------------------------------+
| Port  | Protocol                     | Transport | Description                                      |
+-------+------------------------------+-----------+--------------------------------------------------+
| 25    | smtp                         | tcp       | Simple Mail Transfer                             |
| 465   | urd                          | tcp       | URL Rendezvous Directory for SSM                 |
| 587   | submission                   | tcp       | Message Submission                               |
| 993   | imaps                        | tcp       | IMAP over TLS protocol                           |
| 995   | pop3s                        | tcp       | POP3 over TLS protocol                           |
+-------+------------------------------+-----------+--------------------------------------------------+
[+] Portscan finished
[+] Report for imap.gmail.com completed
```
