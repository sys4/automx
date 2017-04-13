#!/bin/bash
#
# automx - auto configuration service
# Copyright (c) 2011-2013 [*] sys4 AG
#
# Authors: Christian Roessner, Patrick Ben Koetter, Marc Schiffbauer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
VERSION="1.1.1"

trap clean_exit EXIT
function clean_exit() {
	[[ -f "$OLREQUEST" ]] && rm "$OLREQUEST"
	[[ -f "$MBREQUEST" ]] && rm "$MBREQUEST"
	[[ -f "$MBCRESPONSE" ]] && rm "$MBCRESPONSE"
}

# We need a mail address
if [[ $1 ]]; then
	PROFILE="$1"
else
	echo "Provide the mail address for which configuration settings should be retrieved."
	read -ep "Mail address: " PROFILE
fi

DOMAIN="${PROFILE#*@}"
PROGRAM_NAME=$(basename $0)
OLREQUEST="$(mktemp /tmp/${PROGRAM_NAME}.XXXXXX)"
MBREQUEST="$(mktemp /tmp/${PROGRAM_NAME}.XXXXXX)"
MBCRESPONSE="$(mktemp /tmp/${PROGRAM_NAME}.XXXXXX)"

# Test Mozilla schema
MOZFOUND=0
AUTOCONF="autoconfig.$DOMAIN"
WELL_KNOWN="$DOMAIN/.well-known/autoconfig"
if [[ ! $(dig +short $AUTOCONF) ]]; then
	echo
	echo "Autodiscovery domain for Mozilla Thunderbird not found ($AUTOCONF)"
	echo
else
	CON="http://$AUTOCONF/mail/config-v1.1.xml?emailaddress=$PROFILE"
	echo
	echo "Testing Autoconfig ..."
	echo "Connecting to $CON ..."
	echo
	wget -S -O - -q --no-check-certificate $CON && MOZFOUND=1
fi
if [ $MOZFOUND -ne 1 ]; then
	# some error happened; try fallback URL
	echo "Trying fallback URL ..."
	CON="http://$WELL_KNOWN/mail/config-v1.1.xml?emailaddress=$PROFILE"
	echo "Connecting to $CON ..."
	echo
	wget -S -O - -q --no-check-certificate $CON && MOZFOUND=1
fi
if [ $MOZFOUND -eq 0 ]; then
	# no supported autoconfig information
	echo "No autoconfig endpoint found."
	echo
fi


# Test Microsoft schema
AUTODISC="autodiscover.$DOMAIN"
if [[ -z $(dig +short $AUTODISC) ]]; then
	# default domain does not exist, try to discover non-default
	AUTODISC="$(dig +short -t srv _autodiscover._tcp.$DOMAIN)"
  	AUTODISC="${AUTODISC//* /}"
  	AUTODISC="${AUTODISC%.*}"
fi
if [[ $AUTODISC ]]; then
	# Test Microsoft Outlook schema
	CON="https://$AUTODISC/autodiscover/autodiscover.xml"
	cat <<-REQ >$OLREQUEST
		<?xml version="1.0" encoding="utf-8"?>
		<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
		  <Request>
		    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
		    <EMailAddress>$PROFILE</EMailAddress>
		  </Request>
		</Autodiscover>
	REQ

	echo
	echo "Testing Autodiscover (Microsoft Outlook(tm)) ..."
	echo "Connecting to $CON ..."
	echo
	wget -S -O - -q --post-file=$OLREQUEST --no-check-certificate $CON
	rm $OLREQUEST

	# Test Microsoft Mobile schema
	cat <<-REQ >$MBREQUEST
		<?xml version="1.0" encoding="utf-8"?>
		<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006">
		  <Request>
		    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006</AcceptableResponseSchema>
		    <EMailAddress>$PROFILE</EMailAddress>
		  </Request>
		</Autodiscover>
	REQ

	echo
	echo "Testing Autodiscover (mobilesync) ..."
	echo "Connecting to $CON ..."
	echo
	wget -S -O - -q --post-file=$MBREQUEST --no-check-certificate $CON
	rm $MBREQUEST
else
	echo
	echo "Autodiscovery domain for Microsoft Outlook(tm) not found (autodiscover.$DOMAIN)"
	echo
fi

# Test mobileconfig schema
AUTODISC="autodiscover.$DOMAIN"
if [[ -z $(dig +short $AUTODISC) ]]; then
	# default domain does not exist, try to discover non-default
	AUTODISC="$(dig +short -t srv _autodiscover._tcp.$DOMAIN)"
  	AUTODISC="${AUTODISC//* /}"
  	AUTODISC="${AUTODISC%.*}"
fi
if [[ $AUTODISC ]]; then
	# Test Apple mobileconfig schema
	CON="https://$AUTODISC/mobileconfig"

	echo -n "_mobileconfig=true&cn=&emailaddress=$PROFILE&password=" > $MBREQUEST

	echo
	echo "Testing mobileconfig..."
	echo "Connecting to $CON ..."
	echo
	wget -S -O - -q --post-file=$MBREQUEST --no-check-certificate $CON | hexdump -C
else
	echo
	echo "Domain for iOS(tm) not found ($DOMAIN)"
	echo
fi
# EOF
