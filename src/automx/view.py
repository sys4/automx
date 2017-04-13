"""
automx - auto configuration service
Copyright (c) 2011-2013 [*] sys4 AG

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import uuid
import logging

from lxml import etree
from lxml.etree import XMLSyntaxError
from xml.parsers.expat import ExpatError

try:
    # noinspection PyUnresolvedReferences
    from plistlib import load, dumps, FMT_XML
except ImportError:
    # noinspection PyPep8Naming
    from plistlib import readPlist, writePlistToString


__version__ = '1.1.1'
__author__ = "Christian Roessner, Patrick Ben Koetter"
__copyright__ = "Copyright (c) 2011-2015 [*] sys4 AG"


class View(object):
    """
    The view class uses the data structure built with the model class Config.
    It can convert data into different XML outputs. It currently supports
    AutoDiscover as found in the Microsoft world as well as Autoconfig, which
    is used in Mozilla Thunderbird and several other open-source MUAs. It also
    supports .mobileconfig profile support as found on iOS devices. These
    profiles can also be used on Mac OS X Mail.app

    """

    def __init__(self, model, schema, subschema):
        self.__model = model
        self.__schema = schema
        self.__subschema = subschema

        self.__xml = None
        self.__plist = None

    # noinspection PyPep8Naming
    def __build_xml_plist_tree(self):
        if self.__schema in self.__model.domain:
            if self.__schema in ("autodiscover", "autoconfig"):
                path = self.__model.domain[self.__schema]
                try:
                    tree = etree.parse(path)
                    root = tree.getroot()
                    self.__xml = root
                except XMLSyntaxError:
                    logging.error("Syntax error in file %s" % path)

            elif self.__schema == "mobileconfig":
                path = self.__model.domain[self.__schema]
                try:
                    if sys.version_info < (3,):
                        plist_tmp = readPlist(path)
                    else:
                        plist_tmp = load(path)
                    plist = plist_tmp.copy()
                    self.__plist = plist
                except ExpatError:
                    logging.error("Syntax error in file %s" % path)

        elif self.__schema == "autodiscover":
            # define namespace constant
            NS_AutoDiscover = ("http://schemas.microsoft.com/exchange/"
                               "autodiscover/responseschema/2006")

            if self.__subschema == "outlook":
                NS_Response = ("http://schemas.microsoft.com/exchange/"
                               "autodiscover/outlook/responseschema/2006a")

                root = etree.Element("Autodiscover", xmlns=NS_AutoDiscover)
                response = etree.SubElement(root,
                                            "Response",
                                            xmlns=NS_Response)

                if ("display_name" in self.__model.domain or
                        ("smtp" in self.__model.domain and
                         "smtp_author" in self.__model.domain["smtp"][0])):

                    user = etree.SubElement(response, "User")

                    if "display_name" in self.__model.domain:
                        displayname = etree.SubElement(user, "DisplayName")
                        displayname.text = self.__model.domain["display_name"]

                    if "smtp" in self.__model.domain:
                        smtp = self.__model.domain["smtp"]

                        if "smtp_author" in smtp[0]:
                            email = smtp[0]["smtp_author"]

                            smtp_author = etree.SubElement(
                                user, "AutoDiscoverSMTPAddress")
                            smtp_author.text = email

                account = etree.SubElement(response, "Account")

                if "account_type" in self.__model.domain:
                    account_type = etree.SubElement(account, "AccountType")
                    account_type.text = self.__model.domain["account_type"]
                else:
                    raise Exception("Missing attribute <account_type>")

                if "action" in self.__model.domain:
                    action = etree.SubElement(account, "Action")
                    action.text = self.__model.domain["action"]
                else:
                    raise Exception("Missing attribute <action>")

                for key, value in self.__model.domain.items():
                    if key in ("smtp", "imap", "pop", "caldav", "carddav", "ox"):
                        if len(value) != 0:
                            protocol = etree.SubElement(account, "Protocol")
                            self.__service(key, protocol)

                self.__xml = root

            elif self.__subschema == "mobile":
                NS_Response = ("http://schemas.microsoft.com/exchange/"
                               "autodiscover/mobilesync/responseschema/2006")

                root = etree.Element("Autodiscover", xmlns=NS_AutoDiscover)
                response = etree.SubElement(root,
                                            "Response",
                                            xmlns=NS_Response)

                # TODO: do we need a Culture option?
                culture = etree.SubElement(response, "Culture")
                culture.text = "en:us"

                user = etree.SubElement(response, "User")

                if "display_name" in self.__model.domain:
                    displayname = etree.SubElement(user, "DisplayName")
                    displayname.text = self.__model.domain["display_name"]

                emailaddress = etree.SubElement(user, "EmailAddress")
                emailaddress.text = self.__model.domain["emailaddress"]

                action = etree.SubElement(response, "Action")

                settings = etree.SubElement(action, "Settings")

                server = etree.SubElement(settings, "Server")

                servertype = etree.SubElement(server, "Type")
                servertype.text = "MobileSync"

                if "server_url" in self.__model.domain:
                    serverurl = etree.SubElement(server, "Url")
                    serverurl.text = self.__model.domain["server_url"]

                if "server_name" in self.__model.domain:
                    servername = etree.SubElement(server, "Name")
                    servername.text = self.__model.domain["server_name"]
                elif "server_url" in self.__model.domain:
                    servername = etree.SubElement(server, "Name")
                    servername.text = self.__model.domain["server_url"]

                self.__xml = root

            else:
                return

        elif self.__schema == "autoconfig":
            root = etree.Element("clientConfig", version="1.1")

            provider = etree.SubElement(root,
                                        "emailProvider",
                                        id=self.__model.provider)

            domain = etree.SubElement(provider, "domain")
            if "domain" in self.__model.domain:
                domain.text = self.__model.domain["domain"]

            display_name = etree.SubElement(provider, "displayName")
            if "account_name" in self.__model.domain:
                display_name.text = self.__model.domain["account_name"]

            display_short = etree.SubElement(provider, "displayShortName")
            if "account_name_short" in self.__model.domain:
                display_short.text = self.__model.domain["account_name_short"]

            for key, value in self.__model.domain.items():
                if key in ("smtp", "imap", "pop"):
                    if len(value) != 0:
                        self.__service(key, provider)

            self.__xml = root

        elif self.__schema == "mobileconfig":
            proto = dict()

            # We only support IMAP or POP3.
            service_configured = False

            for key, value in self.__model.domain.items():
                if not service_configured and key == "imap":
                    if len(value) != 0:
                        self.__service(key, None, proto)
                        service_configured = True

                elif not service_configured and key == "pop":
                    if len(value) != 0:
                        self.__service(key, None, proto)
                        service_configured = True

                if key == "smtp":
                    if len(value) != 0:
                        self.__service(key, None, proto)

            if "account_name" in self.__model.domain:
                org = self.__model.domain["account_name"]
            else:
                org = self.__model.provider

            email_account_name = self.__model.cn
            if "display_name" in self.__model.domain:
                if self.__model.cn == "":
                    email_account_name = self.__model.domain["display_name"]

            rev_provider = self.__model.provider.split(".")
            rev_provider = ".".join(rev_provider[::-1])
            rev_email = self.__model.emailaddress.split("@")
            rev_email = ".".join(rev_email[::-1])
            payload_identifier = ("org.automx.mail." +
                                  rev_provider +
                                  "." +
                                  rev_email)

            s = dict(EmailAccountDescription=org,
                     EmailAccountName=email_account_name,
                     EmailAccountType=proto["type"],
                     EmailAddress=self.__model.emailaddress,
                     IncomingMailServerAuthentication=proto["in_auth"],
                     IncomingMailServerHostName=proto["in_server"],
                     IncomingMailServerPortNumber=proto["in_port"],
                     IncomingMailServerUseSSL=proto["in_encryption"],
                     IncomingMailServerUsername=proto["in_username"],
                     IncomingPassword=self.__model.password,
                     OutgoingMailServerAuthentication=proto["out_auth"],
                     OutgoingMailServerHostName=proto["out_server"],
                     OutgoingMailServerPortNumber=proto["out_port"],
                     OutgoingMailServerUseSSL=proto["out_encryption"],
                     OutgoingMailServerUsername=proto["out_username"],
                     OutgoingPasswordSameAsIncomingPassword=True,
                     PayloadDescription="Configure email account.",
                     PayloadDisplayName="IMAP Account (%s)" % org,
                     PayloadIdentifier=payload_identifier,
                     PayloadOrganization=self.__model.provider,
                     PayloadType="com.apple.mail.managed",
                     PayloadUUID=str(uuid.uuid4()),
                     PayloadVersion=1,
                     PreventAppSheet=False,
                     PreventMove=False,
                     SMIMEEnabled=False)

            self.__plist = dict(PayloadContent=[s],
                                PayloadDescription="Automx Email",
                                PayloadDisplayName=org,
                                PayloadIdentifier=payload_identifier,
                                PayloadOrganization=self.__model.provider,
                                PayloadRemovalDisallowed=False,
                                PayloadType="Configuration",
                                PayloadUUID=str(uuid.uuid4()),
                                PayloadVersion=1)

    def __service(self, service, root, proto=None):
        l = self.__model.domain[service]

        if self.__schema == "autodiscover":
            # we assume, autodiscover only supports single protocols! So we
            # only use the first defined list element
            elem = l[0]

            c = etree.SubElement(root, "Type")

            s_type = None
            if service in ("smtp", "imap"):
                s_type = service.upper()
            elif service in "pop":
                s_type = "POP3"
            elif service in "caldav":
                s_type = "CalDAV"
            elif service in "carddav":
                s_type = "CardDAV"
            elif service in "ox":
                s_type = "X-OX-APPSUITE"

            c.text = s_type

            if service + "_server" in elem:
                c = etree.SubElement(root, "Server")
                c.text = elem[service + "_server"]

            if service + "_port" in elem:
                c = etree.SubElement(root, "Port")
                c.text = elem[service + "_port"]

            c = etree.SubElement(root, "DomainRequired")
            if service + "_domain_required" in elem:
                c.text = elem[service + "_domain_required"]
            else:
                c.text = "off"
            if service + "_domain_name" in elem:
                c = etree.SubElement(root, "DomainName")
                c.text = elem[service + "_domain_name"]

            if service + "_auth_identity" in elem:
                c = etree.SubElement(root, "LoginName")
                c.text = elem[service + "_auth_identity"]

            if service + "_auth" in elem:
                c = etree.SubElement(root, "SPA")

                value = elem[service + "_auth"]

                if value != "cleartext":
                    spa = "on"
                else:
                    spa = "off"

                c.text = spa

            if service + "_encryption" in elem:
                c = etree.SubElement(root, "Encryption")

                value = elem[service + "_encryption"]

                if value == "none":
                    ssl = "None"
                elif value == "ssl":
                    ssl = "SSL"
                elif value == "starttls":
                    ssl = "TLS"
                elif value == "auto":
                    ssl = "Auto"
                else:
                    # anything that we can not understand leads into "None"
                    ssl = "None"

                c.text = ssl

            c = etree.SubElement(root, "AuthRequired")
            if service + "_auth" in elem:
                c.text = "on"
            else:
                c.text = "off"

            if service + "_expiration_date" in elem:
                c = etree.SubElement(root, "ExpirationDate")
                c.text = elem[service + "_expiration_date"]

            if service + "_refresh_ttl" in elem:
                c = etree.SubElement(root, "TTL")
                c.text = elem[service + "_refresh_ttl"]

            if service == "smtp":
                if (service + "_auth" in elem and
                        elem[service + "_auth"] == "smtp-after-pop"):
                    c = etree.SubElement(root, "SMTPLast")
                    c.text = "on"

        elif self.__schema == "autoconfig":
            for elem in iter(l):
                if service == "smtp":
                    sub_root = etree.SubElement(root,
                                                "outgoingServer",
                                                type=service)
                elif service == "imap":
                    sub_root = etree.SubElement(root,
                                                "incomingServer",
                                                type=service)
                elif service == "pop":
                    sub_root = etree.SubElement(root,
                                                "incomingServer",
                                                type="pop3")

                if service + "_server" in elem:
                    c = etree.SubElement(sub_root, "hostname")
                    c.text = elem[service + "_server"]

                if service + "_port" in elem:
                    c = etree.SubElement(sub_root, "port")
                    c.text = elem[service + "_port"]

                if service + "_encryption" in elem:
                    c = etree.SubElement(sub_root, "socketType")

                    value = elem[service + "_encryption"]

                    if value in ("ssl", "starttls"):
                        c.text = value.upper()
                    elif value in ("none", "auto"):
                        # autoconfig does not know anything about auto
                        c.text = "plain"

                if service + "_auth" in elem:
                    c = etree.SubElement(sub_root, "authentication")

                    value = elem[service + "_auth"]
                    result = ""

                    if value == "cleartext":
                        result = "password-cleartext"
                    elif value == "encrypted":
                        result = "password-encrypted"
                    elif value == "ntlm":
                        result = "NTLM"
                    elif value == "gssapi":
                        result = "GSSAPI"
                    elif value == "client-ip-address":
                        result = "client-IP-address"
                    elif value == "tls-client-cert":
                        result = "TLS-client-cert"
                    elif value == "none":
                        result = "none"
                    elif value == "smtp-after-pop":
                        if service == "smtp":
                            result = "SMTP-after-POP"

                    c.text = result

                if service + "_auth_identity" in elem:
                    c = etree.SubElement(sub_root, "username")
                    c.text = elem[service + "_auth_identity"]

                if service == "smtp":
                    if service + "_default" in elem:
                        value = elem[service + "_default"]

                        c = etree.SubElement(sub_root,
                                             "useGlobalPreferredServer")
                        c.text = value.lower()

        elif self.__schema == "mobileconfig":
            # see autodiscover comment above
            elem = l[0]

            if service == "imap":
                proto["type"] = "EmailTypeIMAP"
            if service == "pop":
                proto["type"] = "EmailTypePOP"

            if service + "_server" in elem:
                if service in ("imap", "pop"):
                    proto["in_server"] = elem[service + "_server"]
                elif service == "smtp":
                    proto["out_server"] = elem[service + "_server"]

            if service + "_port" in elem:
                if service in ("imap", "pop"):
                    proto["in_port"] = int(elem[service + "_port"])
                elif service == "smtp":
                    proto["out_port"] = int(elem[service + "_port"])

            if service + "_auth_identity" in elem:
                if service in ("imap", "pop"):
                    proto["in_username"] = elem[service + "_auth_identity"]
                elif service == "smtp":
                    proto["out_username"] = elem[service + "_auth_identity"]

            if service + "_auth" in elem:
                value = elem[service + "_auth"]
                result = ""

                if value == "cleartext":
                    result = "EmailAuthPassword"
                elif value == "encrypted":
                    # We currently do not support EmailAuthHTTPMD5
                    result = "EmailAuthCRAMMD5"
                elif value == "ntlm":
                    result = "EmailAuthNTLM"
                elif value == "gssapi":
                    # Not supported
                    pass
                elif value == "client-ip-address":
                    # Not supported
                    pass
                elif value == "tls-client-cert":
                    # Not supported
                    pass
                elif value == "none":
                    result = "EmailAuthNone"

                if service in ("imap", "pop"):
                    proto["in_auth"] = result
                elif service == "smtp":
                    proto["out_auth"] = result

            if service + "_encryption" in elem:
                value = elem[service + "_encryption"]

                if value in ("ssl", "starttls"):
                    if service in ("imap", "pop"):
                        proto["in_encryption"] = True
                    elif service == "smtp":
                        proto["out_encryption"] = True
                else:
                    if service in ("imap", "pop"):
                        proto["in_encryption"] = False
                    elif service == "smtp":
                        proto["out_encryption"] = False

    def render(self):
        """Return the XML result of the view as a character string.
        """
        self.__build_xml_plist_tree()

        if self.__xml is not None:
            return etree.tostring(self.__xml,
                                  xml_declaration=True,
                                  method="xml",
                                  encoding="utf-8",
                                  pretty_print=True)

        elif self.__plist is not None:
            if sys.version_info < (3,):
                plist_unsigned = writePlistToString(self.__plist)
            else:
                # noinspection PyArgumentList
                plist_unsigned = dumps(self.__plist, fmt=FMT_XML)

            # Old M2Crypto that is not ported yet to Python3
            """
                    sign_cert = self.__model.domain["sign_cert"]
                    sign_key = self.__model.domain["sign_key"]

                    buffer = M2Crypto.BIO.MemoryBuffer(plist_unsigned)
                    signer = M2Crypto.SMIME.SMIME()
                    s = M2Crypto.X509.X509_Stack()

                    cert_handle = open(sign_cert).read()
                    certificates = re.finditer(r"-----BEGIN CERTIFICATE-----"
                                                ".*?-----END CERTIFICATE-----",
                                                cert_handle, re.S)

                    # First certificate is for signing!
                    # Rest is intermediate cert chain!
                    certificates.next()
                    for match in certificates:
                        s.push(M2Crypto.X509.load_cert_string(match.group(0)))
                    signer.set_x509_stack(s)

                    # Load key and _first_ certificate
                    try:
                        signer.load_key(sign_key, sign_cert)
                    except M2Crypto.BIO.BIOError:
                        logging.error("Cannot access %s or %s. Not signing!"
                                      % (sign_cert, sign_key))
                        return plist_unsigned

                    p7 = signer.sign(buffer)
                    output = M2Crypto.BIO.MemoryBuffer()
                    p7.write_der(output)
                    plist_signed = output.getvalue()

                    return plist_signed
            """

            if "sign_mobileconfig" in self.__model.domain:
                if (self.__model.domain["sign_mobileconfig"] is True and
                        "sign_cert" in self.__model.domain and
                        "sign_key" in self.__model.domain):

                    sign_cert = self.__model.domain["sign_cert"]
                    sign_key = self.__model.domain["sign_key"]

                    if "sign_more_certs" in self.__model.domain:
                        extra = " -certfile " + self.__model.domain[
                            "sign_more_certs"]
                    else:
                        extra = ""

                    import subprocess as s

                    cmd = self.__model.openssl + \
                        " smime -sign -nodetach -outform der -aes-256-cbc" \
                        " -signer " + sign_cert + " -inkey " + sign_key + \
                        extra
                    process = s.Popen(
                        cmd.split(), stdin=s.PIPE, stdout=s.PIPE, stderr=s.PIPE)

                    plist_signed, errors = process.communicate(
                        input=plist_unsigned)
                    if errors not in (b"", None):
                        logging.warning("openssl: %s", str(errors))

                    return plist_signed
                else:
                    logging.info("Not signing!")

            return plist_unsigned
        else:
            return ""

# vim: expandtab ts=4 sw=4
