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

import os
import sys
import shlex
import re
import logging
# noinspection PyCompatibility
import ipaddress

try:
    import configparser
except ImportError:
    # noinspection PyPep8Naming
    import ConfigParser as configparser

try:
    # noinspection PyUnresolvedReferences
    import memcache

    use_memcache = True
except ImportError:
    use_memcache = False

# noinspection PyCompatibility
from configparser import NoOptionError, NoSectionError
from dateutil import parser
from collections import OrderedDict
# noinspection PyCompatibility
from builtins import dict, int, str


__version__ = '1.1.1'
__author__ = "Christian Roessner, Patrick Ben Koetter"
__copyright__ = "Copyright (c) 2011-2015 [*] sys4 AG"

# List of boolean words that have the meaning "true"
TRUE = ('1', 'y', 'yes', 't', 'true', 'on')


class DataNotFoundException(Exception):
    pass


class ConfigNotFoundException(Exception):
    pass


class Config(configparser.RawConfigParser):
    """
    This class creates the internal data structure that is completely
    independend from the view. It may query different backends to gather all
    required information needed to generate XML output later on in the view
    class.

    It uses a OrderdDict to guarentee the correct service order that is needed
    in the XML output. This said means that it is a difference, if a service
    like IMAP is configured before POP3 or upside down, because a MUA follows
    this order.

    The class currently support smtp, pop, imap, carddav, caldav and ox services.

    The class currently supports the following backends:

    -> global - This backend tells automx to use the global section

    -> static - all kind of service information that can be sent directly to
                the MUA

    -> filter - This backend can execute commands and collects results from
                stdout. The result may be "", which means we skip further
                searching. It may return data, which should point to a section
                that we try to follow.

    -> ldap   - Read all kind of information from LDAP servers. The result
                attributes are stored in an internal dictionary and if options
                later on in this backend section (is read as static backend)
                do contain variables in the form ${attributename}, these are
                expanded to the collected data.

    -> sql    - Read all kind of information from SQL servers. The result
                attributes are stored in an internal dictionary. See ldpa

    -> script - Execute a script and split a result into attributes, which are
                stored in an internal dictionary, See ldap

    -> file   - Provide static files. If present, all collected data are
                discarded and only the static file is sent to the remote
                client. This may change in future releases.

    Note: There may exist a DEFAULT section that is appended to _all_ sections
    in the configuration file. That said you can do really complex
    configurations that on the other hand make life easier. This section also
    may contain variables, which, if found in the vars-dictionary, are used.

    """

    def __init__(self, environ):
        # noinspection PyCallByClass,PyTypeChecker
        configparser.RawConfigParser.__init__(self,
                                              defaults=None,
                                              dict_type=OrderedDict)

        found_conf = False
        conf_files = list(["/usr/local/etc/automx.conf", "/etc/automx.conf"])

        conf = None
        for conf in iter(conf_files):
            if os.path.exists(conf):
                found_conf = True
                break

        if not found_conf:
            raise ConfigNotFoundException("No configuration files found:"
                                          "%s, %s" %
                                          (conf_files[0], conf_files[1]))
        self.read(conf)

        if not self.has_section("automx"):
            raise Exception("Missing section 'automx'")

        if self.has_option("automx", "logfile"):
            self.logfile = self.get("automx", "logfile")
        else:
            self.logfile = None

        if self.has_option("automx", "debug"):
            self.debug = self.getboolean("automx", "debug")
        else:
            self.debug = False

        # We need a home directory for the OpenSSL-rand file
        if self.has_option("automx", "homedir"):
            os.environ["HOME"] = self.get("automx", "homedir")
        else:
            os.environ["HOME"] = "/var/automx"

        self.memcache = Memcache(self, environ)

        # defaults
        self.__emailaddress = ""
        self.__cn = ""
        self.__password = ""
        self.__search_domain = ""
        self.__automx = dict()

        # domain individual settings (overwrites some or all defaults)
        self.__domain = OrderedDict()

        # if we use dynamic backends, we might earn variables
        self.__vars = dict()

    def configure(self, emailaddress, cn=None, password=None):
        if emailaddress is None:
            return OrderedDict()

        # Full email address containing local part _and_ domain
        self.__emailaddress = emailaddress

        # Mobileconfig
        if cn is not None:
            self.__cn = cn
        if password is not None:
            self.__password = password

        # The domain that is searched in the config file
        domain = emailaddress.split("@")[1]
        self.__search_domain = domain

        try:
            provider = self.get("automx", "provider")

            # provider must be a domainname
            pattern = "^[0-9a-zA-Z.-]+[a-zA-Z]{2,9}$"
            prog = re.compile(pattern)
            result = prog.match(provider)
            if result is not None:
                self.__automx["provider"] = result.group(0)
            else:
                logging.error("<provider> setting broken!")
                self.__automx["provider"] = "provider.broken"

            tmp = self.create_list(self.get("automx", "domains"))
            self.__automx["domains"] = tmp
        except TypeError:
            raise Exception("Missing options in section automx")

        try:
            self.__automx["openssl"] = self.get("automx", "openssl")
        except (NoSectionError, NoOptionError):
            self.__automx["openssl"] = "/usr/bin/openssl"

        # if a domain has its own section, use settings from it
        cmp_domains = [dom.lower() for dom in self.__automx["domains"]]
        if (domain.lower() in iter(cmp_domains) or
                self.__automx["domains"][0] == "*"):
            cmp_sections = [dom.lower() for dom in self.sections()]
            if domain.lower() in iter(cmp_sections):
                self.__eval_options(domain)
            else:
                if self.has_section("global"):
                    self.__eval_options("global")
                else:
                    raise Exception("Missing section 'global'")
                # we need to use default values from config file
                self.__domain = self.__replace_makro(self.__domain)

    def __eval_options(self, section, backend=None):
        settings = self.__domain

        settings["domain"] = self.__search_domain
        settings["emailaddress"] = self.__emailaddress

        section = self.__find_section(section)

        if self.has_option(section, "backend"):
            if backend is None:
                try:
                    backend = self.get(section, "backend")
                except NoOptionError:
                    raise Exception("Missing option <backend>")

            if backend in ("static", "static_append"):
                for opt in iter(self.options(section)):
                    if opt in ("action",
                               "account_type",
                               "account_name",
                               "account_name_short",
                               "display_name",
                               "server_url",
                               "server_name"):
                        tmp = self.get(section, opt)
                        result = self.__expand_vars(tmp)
                        result = self.__replace_makro(result)
                        settings[opt] = result
                    elif opt == "smtp":
                        service = self.__service(section, "smtp")
                    elif opt == "imap":
                        service = self.__service(section, "imap")
                    elif opt == "pop":
                        service = self.__service(section, "pop")
                    elif opt == "carddav":
                        service = self.__service(section, "carddav")
                    elif opt == "caldav":
                        service = self.__service(section, "caldav")
                    elif opt == "ox":
                        service = self.__service(section, "ox")
                    elif opt == "sign_mobileconfig":
                        try:
                            settings[opt] = self.getboolean(section, opt)
                        except (NoSectionError, NoOptionError, ValueError):
                            logging.error("%s is not boolean!" % opt)
                            settings[opt] = False
                    elif opt in ("sign_cert", "sign_key", "sign_more_certs"):
                        result = self.get(section, opt)
                        if os.path.exists(result):
                            settings[opt] = result
                        else:
                            logging.error("%s cannot read %s" % (opt, result))
                    else:
                        pass

                    if opt in ("smtp", "imap", "pop", "caldav", "carddav", "ox"):
                        if backend == "static_append":
                            if opt in settings:
                                if self.debug:
                                    logging.debug("APPEND %s" % service)
                                settings[opt].append(service)
                            else:
                                if self.debug:
                                    logging.debug("APPEND NEW %s"
                                                  % service)
                                settings[opt] = [service]
                        else:
                            # do not include empty services
                            if len(service) != 0:
                                if self.debug:
                                    logging.debug("STATIC %s" % service)
                                service_category = OrderedDict()
                                service_category[opt] = [service]
                                settings.update(service_category)

                # always follow at the end!
                if "follow" in self.options(section):
                    tmp = self.get(section, "follow")
                    result = self.__expand_vars(tmp)
                    result = self.__replace_makro(result)
                    self.__eval_options(result)

            elif backend in ("ldap", "ldap_append"):
                try:
                    import ldap
                    import ldap.sasl
                except:
                    raise Exception("python ldap missing")

                ldap_cfg = dict(host="ldap://127.0.0.1/",
                                base="",
                                bindmethod="simple",
                                binddn=None,
                                bindpw=None,
                                saslmech=None,
                                authzid="",
                                filter="(objectClass=*)",
                                result_attrs=[],
                                scope="sub",
                                usetls="no",
                                cipher="TLSv1",
                                reqcert="never",
                                cert=None,
                                key=None,
                                cacert=None)

                tls = False
                sasl = False

                for opt in iter(self.options(section)):
                    if opt in ("host",
                               "base",
                               "bindmethod",
                               "binddn",
                               "bindpw",
                               "saslmech",
                               "authzid",
                               "filter",
                               "result_attrs",
                               "scope",
                               "usetls",
                               "cipher",
                               "reqcert",
                               "cert",
                               "key",
                               "cacert"):
                        result = self.get(section, opt)

                        if opt in ("host", "result_attrs"):
                            result = self.create_list(result)

                        ldap_cfg[opt] = result

                # Do we connect with TLS?
                reqcert = None
                if ldap_cfg["usetls"].strip().lower() in TRUE:
                    if ldap_cfg["reqcert"] in ("never",
                                               "allow",
                                               "try",
                                               "demand"):
                        rc = ldap_cfg["reqcert"]
                        if rc == "never":
                            reqcert = ldap.OPT_X_TLS_NEVER
                        elif rc == "allow":
                            reqcert = ldap.OPT_X_TLS_ALLOW
                        elif rc == "try":
                            reqcert = ldap.OPT_X_TLS_TRY
                        elif rc == "demand":
                            reqcert = ldap.OPT_X_TLS_DEMAND

                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, reqcert)
                    ldap.set_option(ldap.OPT_X_TLS_CIPHER_SUITE,
                                    ldap_cfg["cipher"])

                    if ldap_cfg["cacert"] is not None:
                        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
                                        ldap_cfg["cacert"])
                    if ldap_cfg["cert"] is not None:
                        ldap.set_option(ldap.OPT_X_TLS_CERTFILE,
                                        ldap_cfg["cert"])
                    if ldap_cfg["key"] is not None:
                        ldap.set_option(ldap.OPT_X_TLS_KEYFILE,
                                        ldap_cfg["key"])

                    tls = True

                # Are we SASL binding to our servers?
                auth_tokens = None
                if ldap_cfg["bindmethod"] == "sasl":
                    mech = ldap_cfg["saslmech"]

                    if mech is not None:
                        if mech.lower() == "digest-md5":
                            auth_tokens = ldap.sasl.digest_md5(
                                ldap_cfg["binddn"],
                                ldap_cfg["bindpw"])
                        elif mech.lower() == "cram-md5":
                            auth_tokens = ldap.sasl.cram_md5(
                                ldap_cfg["binddn"],
                                ldap_cfg["bindpw"])
                        elif mech.lower() == "external":
                            auth_tokens = ldap.sasl.external(
                                ldap_cfg["authzid"])
                        elif mech.lower() == "gssapi":
                            auth_tokens = ldap.sasl.gssapi(ldap_cfg["authzid"])

                    sasl = True

                con = None

                for server in iter(ldap_cfg["host"]):
                    try:
                        con = ldap.initialize(server)
                        if tls:
                            con.start_tls_s()
                        if sasl:
                            con.sasl_interactive_bind_s("", auth_tokens)
                        else:
                            con.simple_bind_s(ldap_cfg["binddn"],
                                              ldap_cfg["bindpw"])
                    except Exception as e:
                        logging.error("LDAP: %s" % e)
                        continue
                    break

                scope = None
                if con is not None:
                    if ldap_cfg["scope"] in ("sub", "subtree"):
                        scope = ldap.SCOPE_SUBTREE
                    elif ldap_cfg["scope"] in ("one", "onelevel"):
                        scope = ldap.SCOPE_ONELEVEL
                    elif ldap_cfg["scope"] in ("base", "exact"):
                        scope = ldap.SCOPE_BASE

                    s_filter = self.__replace_makro(ldap_cfg["filter"])

                    rid = con.search(ldap_cfg["base"],
                                     scope,
                                     s_filter,
                                     ldap_cfg["result_attrs"])

                    raw_res = con.result(rid, True, 60)
                    if raw_res[0] is None:
                        con.abandon(rid)
                        raise Exception("LDAP server timeout reached")

                    # connection established, we have results
                    self.__vars = dict()

                    # we did not receive data from LDAP
                    if raw_res[1]:
                        for entry in raw_res[1]:
                            for key, value in list(entry[1].items()):
                                # result attributes might be multi values, but
                                # we only accept the first value.
                                self.__vars[key] = str(value[0].decode("utf-8"))
                    else:
                        logging.warning("No LDAP result from server!")
                        raise DataNotFoundException

                    try:
                        con.unbind()
                    except ldap.LDAPError:
                        pass

                if backend == "ldap":
                    self.__eval_options(section, backend="static")
                else:
                    self.__eval_options(section, backend="static_append")

            elif backend in ("sql", "sql_append"):
                try:
                    # noinspection PyPackageRequirements
                    from sqlalchemy.engine import create_engine
                except:
                    raise Exception("python sqlalchemy missing")

                sql_cfg = dict(host=None, query="", result_attrs=[])

                for opt in iter(self.options(section)):
                    if opt in ("host", "result_attrs"):
                        result = self.create_list(self.get(section, opt))
                        sql_cfg[opt] = result

                if self.has_option(section, "query"):
                    query = self.get(section, "query")
                    sql_cfg["query"] = self.__replace_makro(query)
                else:
                    raise Exception("Missing option <query>")

                for con in iter(sql_cfg["host"]):
                    try:
                        engine = create_engine(con)
                        connection = engine.connect()
                    except Exception as e:
                        logging.error("SQL: %s" % e)
                        continue

                    result = connection.execute(sql_cfg["query"])
                    for row in result:
                        keys = list(row.keys())
                        for key in iter(keys):
                            if key in iter(sql_cfg["result_attrs"]):
                                self.__vars[key] = row[key]

                        # Implicit LIMIT 1 here
                        break
                    else:
                        logging.warning("No SQL result from server!")
                        connection.close()
                        raise DataNotFoundException

                    connection.close()

                    break

                if backend == "sql":
                    self.__eval_options(section, backend="static")
                else:
                    self.__eval_options(section, backend="static_append")

            elif backend in ("file", "file_append"):
                for opt in iter(self.options(section)):
                    if opt in ("autoconfig", "autodiscover", "mobileconfig"):
                        tmp = self.get(section, opt)
                        result = self.__expand_vars(tmp)

                        if os.path.exists(result):
                            settings[opt] = result

                if backend == "file":
                    self.__eval_options(section, backend="static")
                else:
                    self.__eval_options(section, backend="static_append")

            elif backend in ("script", "script_append"):
                if self.has_option(section, "script"):
                    script_args = self.get(section, "script")
                else:
                    raise Exception("Missing option <script>")

                if self.has_option(section, "result_attrs"):
                    result_attrs = self.create_list(self.get(section,
                                                             "result_attrs"))
                else:
                    raise Exception("Missing option <result_attrs>")

                separator = None
                if self.has_option(section, "separator"):
                    separator = self.get(section, "separator")

                cmd = shlex.split(script_args)
                for i, item in enumerate(cmd):
                    cmd[i] = self.__replace_makro(item)

                stdout_fd = sys.__stdout__.fileno()
                pipe_in, pipe_out = os.pipe()
                pid = os.fork()

                recv = None
                result = None
                if pid == 0:
                    # child
                    os.close(pipe_in)
                    os.dup2(pipe_out, stdout_fd)

                    os.execvp(cmd[0], cmd)

                    raise Exception("ERROR in execvp()")
                elif pid > 0:
                    # parent
                    os.close(pipe_out)
                    recv = os.read(pipe_in, 1024)

                    result = os.waitpid(pid, 0)

                # check return code
                if result[1]:
                    raise Exception("ERROR while calling script",
                                    result,
                                    recv.strip())

                if len(recv) == 0:
                    logging.warning("No result from script!")
                    raise DataNotFoundException

                result = recv.strip().split(separator, len(result_attrs))

                for i in range(min(len(result_attrs), len(result))):
                    self.__vars[result_attrs[i]] = result[i].strip()

                if backend == "script":
                    self.__eval_options(section, backend="static")
                else:
                    self.__eval_options(section, backend="static_append")

            # backends beyond this line do not have a follow option #

            elif backend == "filter":
                if self.has_option(section, "section_filter"):
                    tmp = self.create_list(self.get(section, "section_filter"))
                    special_opts = tmp

                    got_data = False

                    for special_opt in iter(special_opts):
                        if self.has_option(section, special_opt):
                            cmd = shlex.split(self.get(section, special_opt))
                            for i, item in enumerate(cmd):
                                cmd[i] = self.__replace_makro(item)

                            stdout_fd = sys.__stdout__.fileno()

                            pipe_in, pipe_out = os.pipe()

                            pid = os.fork()
                            if pid == 0:
                                # child
                                os.close(pipe_in)
                                os.dup2(pipe_out, stdout_fd)

                                os.execvp(cmd[0], cmd)

                                raise Exception("ERROR in execvp()")
                            elif pid > 0:
                                # parent
                                os.close(pipe_out)
                                recv = os.read(pipe_in, 1024)

                                result = os.waitpid(pid, 0)
                            else:
                                continue

                            # check return code
                            if result[1] != 0:
                                raise Exception("ERROR while calling filter",
                                                result,
                                                recv.strip())
                            else:
                                new_emailaddress = recv.strip()

                            # The result seems not to be an email address
                            if '@' not in new_emailaddress:
                                continue

                            if self.debug:
                                logging.debug("Email address from filter: %s"
                                              % new_emailaddress)

                            got_data = True

                            # we replace our search_domain
                            self.__search_domain = special_opt
                            self.__emailaddress = new_emailaddress

                            # recurse again, because we now have a new section
                            # that we need to scan
                            self.__eval_options(special_opt)

                            # we already got a result. Do not continue!
                            break

                    if not got_data:
                        raise DataNotFoundException

            elif backend == "global":
                if self.has_section("global"):
                    self.__eval_options("global")
                    self.__replace_makro(settings)
                else:
                    raise Exception("Missing section 'global'")

            else:
                raise Exception("Unknown backend specified")

    def __service(self, section, service):
        # This method only stores meta information. The results depend on
        # the MUA xml schema specification and is defined in the Viewer-class

        proto_settings = OrderedDict()

        if (self.__expand_vars(self.get(section, service)).strip().lower() in
                TRUE):
            if self.has_option(section, service + "_server"):
                opt = service + "_server"
                result = self.__expand_vars(self.get(section, opt))

                proto_settings[opt] = self.__replace_makro(result)

            if self.has_option(section, service + "_port"):
                opt = service + "_port"
                result = self.__expand_vars(self.get(section, opt))

                proto_settings[opt] = result

            if self.has_option(section, service + "_encryption"):
                opt = service + "_encryption"
                result = self.__expand_vars(self.get(section, opt))

                if result.lower() == "none":
                    result = "none"
                elif result.lower() == "ssl":
                    result = "ssl"
                elif result.lower() == "starttls":
                    result = "starttls"
                elif result.lower() == "auto":
                    result = "auto"

                proto_settings[opt] = result

            if self.has_option(section, service + "_auth"):
                opt = service + "_auth"
                result = self.__expand_vars(self.get(section, opt))

                if result.lower() == "plaintext":
                    result = "cleartext"
                elif result.lower() == "encrypted":
                    result = "encrypted"
                elif result.lower() == "ntlm":
                    result = "ntlm"
                elif result.lower() == "gssapi":
                    result = "gssapi"
                elif result.lower() == "client-ip-address":
                    result = "client-ip-address"
                elif result.lower() == "tls-client-cert":
                    result = "tls-client-cert"
                elif result.lower() == "none":
                    result = "none"
                elif result.lower() == "smtp-after-pop":
                    if service == "smtp":
                        result = "smtp-after-pop"
                # TODO: we allow bogus keys/values.

                proto_settings[opt] = result

            if self.has_option(section, service + "_auth_identity"):
                opt = service + "_auth_identity"
                result = self.__expand_vars(self.get(section, opt))
                proto_settings[opt] = self.__replace_makro(result)
            else:
                emaillocalpart = self.__replace_makro("%u")
                proto_settings[service + "_auth_identity"] = emaillocalpart

            if self.has_option(section, service + "_expiration_date"):
                opt = service + "_expiration_date"
                result = self.__expand_vars(self.get(section, opt))
                dt = parser.parse(result, fuzzy=True)
                proto_settings[opt] = dt.strftime("%Y%m%d")

            if self.has_option(section, service + "_refresh_ttl"):
                opt = service + "_refresh_ttl"
                result = self.get(section, opt)
                proto_settings[opt] = result

            if self.has_option(section, service + "_domain_required"):
                opt = service + "_domain_required"
                result = self.get(section, opt)
                if result.lower() in TRUE:
                    proto_settings[opt] = "on"
                else:
                    proto_settings[opt] = "off"

            if self.has_option(section, service + "_domain_name"):
                opt = service + "_domain_name"
                result = self.__expand_vars(self.get(section, opt))
                result = self.__replace_makro(result)
                proto_settings[opt] = result

            if service == "smtp":
                if self.has_option(section, service + "_author"):
                    opt = service + "_author"
                    author = self.__expand_vars(self.get(section, opt))

                    if author == "%s":
                        proto_settings[opt] = self.__emailaddress

                if self.has_option(section, service + "_default"):
                    try:
                        opt = service + "_default"
                        tmp = self.__expand_vars(self.get(section, opt))
                        if tmp.strip().lower() in TRUE:
                            result = "Yes"
                        else:
                            result = "No"
                        proto_settings[opt] = result
                    except ValueError:
                        pass

        return proto_settings

    @staticmethod
    def create_list(value):
        result = value.split()

        if len(result) > 1:
            for i, item in enumerate(result):
                result[i] = item.split(",")[0]

        return result

    def __replace_makro(self, expression):
        if "%u" in expression:
            user = self.__emailaddress.split("@")[0]
            expression = expression.replace("%u", user)
        if "%d" in expression:
            domain = self.__search_domain
            expression = expression.replace("%d", domain)
        if "%s" in expression:
            email = self.__emailaddress
            expression = expression.replace("%s", email)

        return expression

    def __expand_vars(self, expression):
        # do we have some dynamic variables?
        if len(self.__vars) == 0:
            return expression

        def repl(mobj):
            if mobj.group(1) in self.__vars:
                _result = self.__vars[mobj.group(1)]

                if mobj.group(2) is not None:
                    macro = mobj.group(2)[1:]

                    if self.debug:
                        logging.debug("__expand_vars()->macro=%s" % macro)

                    if "@" in _result:
                        if macro == "%u":
                            return _result.split("@")[0]
                        if macro == "%d":
                            return _result.split("@")[1]
                        if macro == "%s":
                            return _result

                        _result = _result.split("@")[1]

                    # now the macro may only be part of a FQDN hostname
                    if "." in _result:
                        dcs = _result.split(".")
                        if macro in ("%1", "%2", "%3", "%4", "%5",
                                     "%6", "%7", "%8", "%9"):
                            i = int(macro[1])
                            if len(dcs) < i:
                                return ""

                            return dcs[-i]

                return _result
            else:
                # we always must expand variables. Even if it is the empty
                # string
                return ""

        result = re.sub(r"\$\{(\w+)(:%[sud1-9])?\}",
                        repl,
                        expression,
                        re.UNICODE)

        if self.debug:
            logging.debug("__expand_vars()->result=%s" % result)

        return result

    def __find_section(self, domain):
        l = self.sections()
        for section in iter(l):
            if section.lower() == domain.lower():
                return section

        raise NoSectionError(domain)

    @property
    def provider(self):
        return self.__automx["provider"]

    @property
    def openssl(self):
        return self.__automx['openssl']

    @property
    def domain(self):
        return self.__domain

    @property
    def cn(self):
        return self.__cn

    @property
    def password(self):
        return self.__password

    @property
    def emailaddress(self):
        return self.__emailaddress


class Memcache(object):
    def __init__(self, config, environ):
        self.__config = config
        self.__environ = environ

        # Memcache usage is optional
        self.__has_memcache = use_memcache

        self.__found = False
        self.__client = None
        self.__current = 0

        try:
            if use_memcache:
                self.__mc = memcache.Client([config.get("automx", "memcache")])
        except ValueError as e:
            logging.warning("Memcache misconfigured: ", e)
            self.__has_memcache = False
        except NoOptionError:
            logging.warning("Not using Memcache")
            self.__has_memcache = False

    def counter(self):
        return self.__current

    def set_client(self):
        if not self.__has_memcache:
            return

        if self.__is_trusted_network():
            return

        if self.__config.has_option("automx", "memcache_ttl"):
            try:
                ttl = self.__config.getint("automx", "memcache_ttl")
            except ValueError as e:
                logging.warning("Memcache <memcache_ttl>, using default: ", e)
                ttl = 600
        else:
            ttl = 600

        if self.__found:
            self.__current += 1

        self.__mc.set(self.__client, self.__current, time=ttl)

    def allow_client(self):
        if not self.__has_memcache:
            return True

        self.__client = self.__environ["REMOTE_ADDR"]

        if self.__is_trusted_network():
            if self.__config.debug:
                logging.debug("TRUSTED %s" % self.__client)
            return True
        else:
            if self.__config.debug:
                logging.debug("NOT TRUSTED %s" % self.__client)

        if self.__config.has_option("automx", "client_error_limit"):
            try:
                limit = self.__config.getint("automx", "client_error_limit")
            except ValueError as e:
                logging.warning("Memcache <client_error_limit>, "
                                "using default: ", e)
                limit = 20
        else:
            limit = 20

        result = self.__mc.get(self.__client)

        if result is not None:
            self.__found = True
            self.__current = result

        if self.__current < limit:
            return True
        else:
            self.set_client()
            return False

    def __is_trusted_network(self):
        if self.__config.has_option("automx", "rate_limit_exception_networks"):
            networks = self.__config.get("automx",
                                         "rate_limit_exception_networks")
            networks = self.__config.create_list(networks)
        else:
            networks = ("127.0.0.1", "::1/128")

        if sys.version_info < (3,):
            a = ipaddress.ip_address(self.__client.decode("utf-8"))
        else:
            a = ipaddress.ip_address(self.__client)
        for network in iter(networks):
            n = ipaddress.ip_network(network)
            if a in n:
                if self.__config.debug:
                    logging.debug("FOUND %s, %s" % (a, n))
                return True
            else:
                if self.__config.debug:
                    logging.debug("NOT FOUND %s, %s" % (a, n))

        return False

# vim: expandtab ts=4 sw=4
