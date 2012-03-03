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

import os
import sys
import ConfigParser
import subprocess
import shlex
import StringIO
import re

from ConfigParser import NoOptionError

try:
    # Python 2.7
    from collections import OrderedDict
except:
    # Python 2.5 up to Python 2.7
    from automx.ordereddict import OrderedDict


class Config(object, ConfigParser.RawConfigParser):
    """
    This class creates the internal data structure that is completely
    independend from the view. It may query different backends to gather all
    required information needed to generate XML output later on in the view
    class.
    
    It uses a OrderdDict to guarentee the correct service order that is needed
    in the XML output. This said means that it is a difference, if a service
    like IMAP is configured before POP3 or upside down, because a MUA follows
    this order.
    
    The class currently support smtp, pop and imap services.
    
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
    
    Note: There may exist a DEFAULT section that is appended to _all_ sections
    in the configuration file. That said you can do really complex
    configurations that on the other hand make life easier. This section also
    may contain variables, which, if found in the vars-dictionary, are used.
    
    """
    def __init__(self, environ):
        ConfigParser.RawConfigParser.__init__(self,
                                            defaults=None,
                                            dict_type=OrderedDict)
        self.read("/etc/automx.conf")
        
        self.memcache = Memcache(self)

        self.__environ = environ
        
    def configure(self, emailaddress):
        if emailaddress == "":
            return OrderedDict()

        # Full email address containing local part _and_ domain
        self.__emailaddress = emailaddress
        
        domain = emailaddress.split("@")[1]

        # The domain that is searched in the config file
        self.__search_domain = domain
        
        self.__automx = dict()
        # global section parameter
        self.__defaults = OrderedDict()
        # domain individual settings (overwrites some or all defaults)
        self.__domain = OrderedDict()
        
        # if we use dynamic backends, we might earn variables
        self.__vars = None
        
        if self.has_section("automx"):
            try:
                self.__automx["provider"] = self.get("automx", "provider")
                tmp = self.__create_list(self.get("automx", "domains"))
                self.__automx["domains"] = tmp 
            except TypeError:
                raise Exception("Missing options in section automx")
        else:
            raise Exception("Missing section 'automx'")

        # 1. we read default values
        if self.has_section("global"):
            self.__defaults = self.__eval_options("global")
        else:
            raise Exception("Missing section 'global'")

        # 2. if a domain has its own section, use settings from it
        if (domain in iter(self.__automx["domains"]) or
            self.__automx["domains"][0] == "*"):
            if self.has_section(domain):
                self.__domain = self.__eval_options(domain)
            else:
                # we need to use default values from config file
                self.__domain = self.__defaults
                    
    def __eval_options(self, section, backend=None):
        settings = OrderedDict()

        settings["domain"] = self.__search_domain
        settings["emailaddress"] = self.__emailaddress
        
        if self.has_option(section, "backend"):
            if backend is None:
                try:
                    backend = self.get(section, "backend")
                except NoOptionError:
                    raise Exception("Missing option <backend>")
                
            if backend == "static":
                for opt in iter(self.options(section)):
                    if opt in ("action",
                               "account_type",
                               "account_name",
                               "account_name_short",
                               "display_name"):

                        tmp = self.get(section, opt)
                        result = self.__expand_vars(tmp)

                        settings[opt] = result
                    elif opt == "smtp":
                        settings.update(self.__service(section, "smtp"))
                    elif opt == "imap":
                        settings.update(self.__service(section, "imap"))
                    elif opt == "pop":
                        settings.update(self.__service(section, "pop"))
                    else:
                        pass

            elif backend == "ldap":
                try:
                    import ldap
                    import ldap.sasl
                except:
                    print >> self.__environ['wsgi.errors'], ("python "
                                                             "ldap missing")
                    return OrderedDict()

                ldap_cfg = dict(host = "ldap://127.0.0.1/",
                                base = "",
                                bindmethod = "simple",
                                binddn = None,
                                bindpw = None,
                                saslmech = None,
                                authzid = "",
                                filter = "(objectClass=*)",
                                result_attrs = [],
                                scope = "sub",
                                usetls = "no",
                                cipher = "TLSv1",
                                reqcert ="never",
                                cert = None,
                                key = None,
                                cacert = None)

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
                            result = self.__create_list(result)
                            
                        ldap_cfg[opt] = result
                
                # Do we connect with TLS?
                if ldap_cfg["usetls"].lower() in ("yes", "true", "1"):
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

                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                                    reqcert)
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
                            auth_tokens = ldap.sasl.gssapi(
                                                        ldap_cfg["authzid"])

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
                    except:
                        continue
                    break

                if con is not None:
                    if ldap_cfg["scope"] in ("sub", "subtree"):
                        scope = ldap.SCOPE_SUBTREE
                    elif ldap_cfg["scope"] in ("one", "onelevel"):
                        scope = ldap.SCOPE_ONELEVEL
                    elif ldap_cfg["scope"] in ("base", "exact"):
                        scope = ldap.SCOPE_BASE

                    filter = self.__replace_makro(ldap_cfg["filter"])
                                            
                    try:
                        rid = con.search(ldap_cfg["base"],
                                         scope,
                                         filter,
                                         ldap_cfg["result_attrs"])
                    except Exception, e:
                        print >> self.__environ['wsgi.errors'], e
                        return OrderedDict()
            
                    raw_res = (None, None)
                    raw_res = con.result(rid, True, 60)
                    if raw_res[0] == None:
                        con.abandon(rid)
                        error = "LDAP server timeout reached"
                        print >> self.__environ['wsgi.errors'], error
                        return OrderedDict()

                    # connection established, we have results
                    self.__vars = dict()
                    
                    # we did not receive data from LDAP
                    if raw_res[1] != []:
                        for entry in raw_res[1]:
                            for key, value in entry[1].items():
                                # result attributes might be multi values, but
                                # we only accept the first value.
                                self.__vars[key] = unicode(value[0], "utf-8")
                    else:
                        error = "No LDAP result from server!"
                        print >> self.__environ["wsgi.errors"], error
                        return OrderedDict()

                    try:    
                        con.unbind()
                    except ldap.LDAPError, e:
                        pass

                # then we call ourself again for static addons
                settings.update(self.__eval_options(section,
                                                    backend="static"))
            
            elif backend == "sql":
                try:
                    from sqlalchemy.engine import create_engine
                except:
                    print >> self.__environ['wsgi.errors'], ("python "
                                                             "sqlalchemy "
                                                             "missing")
                    return OrderedDict()

                sql_cfg = dict(host = None, query = "", result_attrs = [])
                
                for opt in iter(self.options(section)):
                    if opt in ("host", "result_attrs"):
                        result = self.__create_list(self.get(section, opt))
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
                    except:
                        continue
                    result = connection.execute(sql_cfg["query"])
                    
                    
                    for row in result:
                        # No data returned
                        if len(row) == 0:
                            return OrderedDict()
                        
                        keys = row.keys()
                        for key in iter(keys):
                            if key in iter(sql_cfg["result_attrs"]):
                                self.__vars[key] = row[key]

                        # Implicit LIMIT 1 here
                        break

                    connection.close()
                    
                    break

                # then we call ourself again for static addons
                settings.update(self.__eval_options(section,
                                                    backend="static"))

            elif backend == "filter":
                if self.has_option(section, "section_filter"):
                    tmp = self.__create_list(self.get(section,
                                                      "section_filter"))
                    special_opts = tmp

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

                            # The result seems not to be a email address
                            if '@' not in new_emailaddress:
                                continue
                            
                            domain = new_emailaddress.split('@')[1]
                            
                            # we replace our search_domain 
                            self.__search_domain = special_opt
                            lpart = self.__emailaddress.split("@")[0]
                            self.__emailaddress = lpart + "@" + domain

                            # recurse again, because we now have a new section
                            # that we need to scan
                            settings.update(self.__eval_options(special_opt))
                            
            elif backend == "global":
                return self.__defaults
            
            elif backend == "file":
                for opt in iter(self.options(section)):
                    if opt in ("autoconfig",
                               "autodiscover"):
                        tmp = self.get(section, opt)
                        result = self.__expand_vars(tmp)
                        
                        if os.path.exists(result):
                            settings[opt] = result

                # then we call ourself again for static addons
                settings.update(self.__eval_options(section,
                                                    backend="static"))
            else:
                raise Exception("Unknown backend specified")

        return settings

    def __service(self, section, service):
        # This method only stores meta information. The results depend on
        # the MUA xml schema specification and is defined in the Viewer-class

        settings = OrderedDict()

        if self.getboolean(section, service) == True:
            if self.has_option(section, service + "_server"):
                opt = service + "_server"
                result = self.__expand_vars(self.get(section, opt))

                settings[opt] = result
                
            if self.has_option(section, service + "_port"):
                opt = service + "_port"
                result = self.__expand_vars(self.get(section, opt))
                
                settings[opt] = result
                
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
                    
                settings[opt] = result
                
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
                
                settings[opt] = result

            if self.has_option(section, service + "_auth_identity"):
                opt = service + "_auth_identity"
                result = self.__expand_vars(self.get(section, opt))
                settings[opt] = self.__replace_makro(result)
            else:
                settings[service + "_auth_identity"] = "%EMAILLOCALPART%"
            
            if service == "smtp":
                if self.has_option(section, service + "_author"):
                    opt = service + "_author"
                    author = self.__expand_vars(self.get(section, opt))

                    if author == "%s":
                        settings[opt] = self.__emailaddress
                    
                if self.has_option(section, service + "_default"):
                    try:
                        opt = service + "_default"
                        tmp = self.__expand_vars(self.get(section, opt))
                        if tmp.lower() in ("yes", "true", "1"):
                            result = "Yes"
                        else:
                            result = "No"
                        settings[opt] = result
                    except ValueError:
                        pass

        service_category = OrderedDict()
        service_category[service] = settings

        return service_category
    
    def __create_list(self, value):
        result = value.split()
        
        if len(result) > 1:
            for i, item in enumerate(result):
                result[i] = item.split(",")[0]
                
        return result
    
    def __replace_makro(self, expression):
        if "%u" in expression:
            user = self.__emailaddress.split("@")[0]
            expression = expression.replace("%u", user)
        elif "%d" in expression:
            domain = self.__search_domain
            expression = expression.replace("%d", domain)
        elif "%s" in expression:
            email = self.__emailaddress
            expression = expression.replace("%s", email)

        return expression

    def __expand_vars(self, expression):
        # do we have some dynamic variables?
        if self.__vars is None:
            return expression
        
        def repl(mobj):
            if self.__vars.has_key(mobj.group(1)):
                return self.__vars[mobj.group(1)]
            else:
                # we always must expand variables. Even if it is the empty
                # string
                return ""

        result = re.sub(r"\$\{(\w+)\}",
                        repl,
                        unicode(expression, "utf-8"),
                        re.UNICODE)
     
        return result
        
    @property
    def provider(self):
        return self.__automx["provider"]

    @property       
    def domain(self):
        return self.__domain

    @property
    def environ(self):
        return self.__environ


class Memcache(object):
    
    def __init__(self, config):
        self.__config = config
        
        # Memcache usage is optional
        self.__has_memcache = True

        self.__client = (None, 0)
        self.__current = 0
        
        try:
            import memcache

            dbg = 1 if config.getboolean("automx", "memcache_debug") else 0
            self.__mc = memcache.Client([config.get("automx", "memcache")],
                                        debug=dbg)
        except ValueError, e:
            print >> config.environ["wsgi.errors"], ("Memcache "
                                                     "misconfigured: ", e)
            self.__has_memcache = False
        except:
            self.__has_memcache = False

    def counter(self):
        return self.__client[1]

    def set_client(self):
        if not self.__has_memcache:
            return

        client, counter = self.__client
        
        if client is not None:
            self.__current = counter + 1
        else:
            return

        try:
            ttl = self.__config.getint("automx", "memcache_ttl")
        except ValueError, e:
            err = self.__config.environ["wsgi.errors"]
            print >> err , "Memcachce <memcache_ttl>: ", e
            return

        self.__mc.set(client, self.__current, time=ttl)
                                                            
    def allow_client(self):
        if not self.__has_memcache:
            return True

        try:
            limit = self.__config.getint("automx", "client_error_limit")
        except ValueError, e:
            err = self.__config.environ["wsgi.errors"]
            print >> err , "Memcachce <client_error_limit>: ", e
            return True
        
        client = self.__config.environ["REMOTE_ADDR"]
        result = self.__mc.get(client)

        if result is not None:
            self.__current = result

        self.__client = (client, self.__current)

        return True if self.__current < limit else False
