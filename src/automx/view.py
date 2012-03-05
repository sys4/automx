"""
automx - auto configuration service
Copyright (C) 2012  state of mind

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

__version__ = '0.8_beta1'
__author__ = "Christian Roessner, Patrick Ben Koetter"
__copyright__ = "Copyright (C) 2012  state of mind"

from lxml import etree
from lxml.etree import XMLSyntaxError


class View(object):
    """
    The view class uses the data structure built with the model class Config.
    It can convert data into different XML outputs. It currently supports
    AutoDiscover as found in the Microsoft world as well as Autoconfig, which
    is used in Mozilla Thunderbird and several other open-source MUAs.
        
    """
    def __init__(self, model, schema, subschema):
        self.__model = model
        self.__schema = schema
        self.__subschema = subschema
        
        self.__xml = None
        
    def __build_xml_tree(self):
        root = None
        
        if self.__model.domain.has_key(self.__schema):
            path = self.__model.domain[self.__schema]
            tree = etree.parse(path)
            root = tree.getroot()
            
        elif self.__schema == "autodiscover":
            # define namespace constant
            NS_AutoDiscover = ("http://schemas.microsoft.com/exchange/"
                               "autodiscover/responseschema/2006")

            if self.__subschema == "outlook":
                NS_Response = ("http://schemas.microsoft.com/exchange/"
                               "autodiscover/outlook/responseschema/2006a")
            else:
                # Maybe we need more information here?
                NS_Response = ("http://schemas.microsoft.com/exchange/"
                               "autodiscover/outlook/responseschema/2006a")
                
            root = etree.Element("Autodiscover", xmlns=NS_AutoDiscover)
            response = etree.SubElement(root, "Response", xmlns=NS_Response)
            
            if (self.__model.domain.has_key("display_name") or
                (self.__model.domain.has_key("smtp") and
                 self.__model.domain["smtp"].has_key("smtp_author"))):
                
                has_user = True
                
                user = etree.SubElement(response, "User")
                
                if self.__model.domain.has_key("display_name"):
                    displayname = etree.SubElement(user, "DisplayName")
                    displayname.text = self.__model.domain["display_name"]

                if self.__model.domain.has_key("smtp"):
                    smtp = self.__model.domain["smtp"]
    
                    if smtp.has_key("smtp_author"):
                        email = smtp["smtp_author"]
    
                        smtp_author = etree.SubElement(user,
                                                   "AutoDiscoverSMTPAddress")
                        smtp_author.text = email

            account = etree.SubElement(response, "Account")

            if self.__model.domain.has_key("account_type"):
                account_type = etree.SubElement(account, "AccountType")
                account_type.text = self.__model.domain["account_type"]
            else:
                raise Exception("Missing attribute <account_type>")
            
            if self.__model.domain.has_key("action"):
                action = etree.SubElement(account, "Action")
                action.text = self.__model.domain["action"]
            else:
                raise Exception("Missing attribute <action>")

            for key, value in self.__model.domain.iteritems():
                if key in ("smtp", "imap", "pop"):
                    if len(value) != 0:
                        protocol = etree.SubElement(account, "Protocol")
                        self.__service(key, protocol)

        elif self.__schema == "autoconfig":
            root = etree.Element("clientConfig", version="1.1")
            
            provider = etree.SubElement(root,
                                        "emailProvider",
                                        id=self.__model.provider)

            domain = etree.SubElement(provider, "domain")
            if self.__model.domain.has_key("domain"):
                domain.text = self.__model.domain["domain"]
            
            display_name = etree.SubElement(provider, "displayName")
            if self.__model.domain.has_key("account_name"):
                display_name.text = self.__model.domain["account_name"]
            
            display_short = etree.SubElement(provider, "displayShortName")
            if self.__model.domain.has_key("account_name_short"):
                display_short.text = self.__model.domain["account_name_short"]

            for key, value in self.__model.domain.iteritems():
                if key in ("smtp", "imap", "pop"):
                    if len(value) != 0:
                        self.__service(key, provider)
    
        self.__xml = root
        
    def __service(self, service, root):
        elem = self.__model.domain[service]

        if self.__schema == "autodiscover":
            c = etree.SubElement(root, "Type")
            
            if service in ("smtp", "imap"):
                type = service.upper()
            elif service in "pop":
                type = "POP3"
            
            c.text = type

            if elem.has_key(service + "_server"):
                c = etree.SubElement(root, "Server")
                c.text = elem[service + "_server"]

            if elem.has_key(service + "_port"):
                c = etree.SubElement(root, "Port")
                c.text = elem[service + "_port"]

            
            c = etree.SubElement(root, "DomainRequired")
            c.text = "off"
            # DomainName - not implemented, yet

            if elem.has_key(service + "_auth_identity"):
                c = etree.SubElement(root, "LoginName")
                c.text = elem[service + "_auth_identity"]
                
            if elem.has_key(service + "_auth"):
                c = etree.SubElement(root, "SPA")

                value = elem[service + "_auth"]
                result = ""

                if value != "cleartext":
                    spa = "on"
                else:
                    spa = "off"
                    
                c.text = spa

            if elem.has_key(service + "_encryption"):
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
            if elem.has_key(service + "_auth"):
                c.text = "on"
            else:
                c.text = "off"

            # We do not support rediscovery
            c = etree.SubElement(root, "TTL")
            c.text = "0"

            if service == "smtp":
                if (elem.has_key(service + "_auth") and
                    elem[service + "_auth"] == "smtp-after-pop"):
                    c = etree.SubElement(root, "SMTPLast")
                    c.text = "on"

        elif self.__schema == "autoconfig":
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
            
            if elem.has_key(service + "_server"):
                c = etree.SubElement(sub_root, "hostname")
                c.text = elem[service + "_server"]

            if elem.has_key(service + "_port"):
                c = etree.SubElement(sub_root, "port")
                c.text = elem[service + "_port"]

            if elem.has_key(service + "_encryption"):
                c = etree.SubElement(sub_root, "socketType")

                value = elem[service + "_encryption"]

                if value in ("ssl", "starttls"):
                    c.text = value.upper()
                elif value in ("none", "auto"):
                    # autoconfig does not know anything about auto
                    c.text = value

            if elem.has_key(service + "_auth"):
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

            if elem.has_key(service + "_auth_identity"):
                c = etree.SubElement(sub_root, "username")
                c.text = elem[service + "_auth_identity"]
                
            if service == "smtp":
                if elem.has_key(service + "_default"):
                    value = elem[service + "_default"]
                    
                    c = etree.SubElement(sub_root, "useGlobalPreferredServer")
                    c.text = value.lower()
                    
    def render(self):
        """Return the XML result of the view as a character string.
        """
        self.__build_xml_tree()

        if self.__xml is not None:
            return etree.tostring(self.__xml,
                                  xml_declaration=True,
                                  method="xml",
                                  encoding="utf-8",
                                  pretty_print=True)
        else:
            return ""
