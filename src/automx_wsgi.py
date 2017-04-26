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
import traceback
import logging

# noinspection PyCompatibility
from html import escape
from io import StringIO
from lxml import etree
from lxml.etree import XMLSyntaxError
# noinspection PyCompatibility
from builtins import int, str

try:
    # noinspection PyCompatibility
    from urllib.parse import urlparse, urlencode, parse_qs, unquote
    # noinspection PyCompatibility
    from urllib.request import urlopen, Request
    # noinspection PyCompatibility
    from urllib.error import HTTPError
except ImportError:
    # noinspection PyCompatibility
    from urlparse import urlparse, parse_qs
    from urllib import urlencode, unquote
    # noinspection PyCompatibility
    from urllib2 import urlopen, Request, HTTPError

from automx.config import Config
from automx.config import DataNotFoundException
from automx.view import View

sys.path.append(os.path.dirname(os.path.realpath(__file__)))


__version__ = '1.1.1'
__author__ = "Christian Roessner, Patrick Ben Koetter"
__copyright__ = "Copyright (c) 2011-2015 [*] sys4 AG"

# HTTP status codes
STAT_OK = "200 OK"
STAT_ERR = "500 Internal Server Error"


def application(environ, start_response):

    response_body = ""
    cn = None
    emailaddress = None
    password = None

    # schema currently may be  'autoconfig', 'autodiscover', 'mobileconfig'
    schema = None

    # subschema currently is either 'mobile' or 'outlook'
    subschema = None

    process = True
    data = None
    status = STAT_OK

    try:
        data = Config(environ)
    except Exception as e:
        process = False
        status = STAT_ERR
        print(e, file=environ["wsgi.errors"])

    if process:
        try:
            logging.basicConfig(filename=data.logfile,
                                format='%(asctime)s %(levelname)s: %(message)s',
                                level=logging.DEBUG)
        except IOError as e:
            print(e, file=environ["wsgi.errors"])

        request_method = environ['REQUEST_METHOD']
        request_method = escape(request_method)

        # Adding some more useful debugging information
        if data.debug:
            logging.debug("-" * 15 + " BEGIN environ " + "-" * 15)
            for k, v in environ.items():
                logging.debug("%s: %s" % (k, v))
            logging.debug("-" * 15 + " END environ " + "-" * 15)

        if request_method == "POST":
            try:
                request_body_size = int(environ.get('CONTENT_LENGTH', 0))
            except ValueError:
                request_body_size = 0

            # When the method is POST the query string will be sent
            # in the HTTP request body which is passed by the WSGI server
            # in the file like wsgi.input environment variable.
            request_body = environ['wsgi.input'].read(request_body_size)

            if data.debug:
                logging.debug("Request POST (raw)\n" +
                              request_body.decode('utf-8'))

            fd = StringIO(request_body.decode("utf-8").replace(
                '<?xml version="1.0" encoding="utf-8"?>', ''))
            try:
                tree = etree.parse(fd)
            except XMLSyntaxError:
                # We did not receive XML, so it might be a mobileconfig request
                # TODO: We also might check the User-Agent here
                d = parse_qs(request_body.decode('utf-8'))

                if d is not None:
                    if data.debug:
                        logging.debug(str(d))
                    if "_mobileconfig" in d:
                        mobileconfig = d["_mobileconfig"][0]
                        if mobileconfig == "true":
                            if data.debug:
                                logging.debug("Requesting mobileconfig "
                                              "configuration")
                            if "cn" in d:
                                cn = d["cn"][0]
                                cn.strip()
                            if "password" in d:
                                password = d["password"][0]
                                password.strip()
                            if "emailaddress" in d:
                                emailaddress = d["emailaddress"][0]
                                emailaddress.strip()
                                status = STAT_OK
                                schema = "mobileconfig"
                            else:
                                logging.warning("Error in mobileconfig "
                                                "request!")
                                process = False
                                status = STAT_ERR
                        else:
                            process = False
                            status = STAT_ERR
                    else:
                        process = False
                        status = STAT_ERR
                else:
                    process = False
                    status = STAT_ERR
            else:
                root = tree.getroot()

                # We need to strip the namespace for XPath
                expr = "//*[local-name() = $name]"

                response_schema = root.xpath(expr,
                                             name="AcceptableResponseSchema")
                if len(response_schema) == 0:
                    logging.warning("Error in XML request")
                    process = False
                    status = STAT_ERR
                    data.memcache.set_client()
                else:
                    # element.text is a http-URI that has a location part
                    # which we need to scan.
                    if "/mobilesync/" in response_schema[0].text:
                        subschema = "mobile"
                    elif "/outlook/" in response_schema[0].text:
                        subschema = "outlook"
                    else:
                        process = False

                    emailaddresses = root.xpath(expr, name="EMailAddress")
                    if len(emailaddresses) == 0:
                        logging.warning("Error in autodiscover request!")
                        process = False
                        status = STAT_ERR
                        data.memcache.set_client()
                    else:
                        emailaddress = emailaddresses[0].text
                        schema = "autodiscover"
                        status = STAT_OK

        elif request_method == "GET":
            # FIXME: maybe we need to catch AutoDiscover GET-REDIRECT requests
            if any("autodiscover" in s for s in (
                    environ["HTTP_HOST"], environ["REQUEST_URI"].lower())):
                process = False
                status = STAT_ERR

            # autoconfig
            else:
                qs = environ['QUERY_STRING']
                d = parse_qs(qs)

                if data.debug:
                    logging.debug("Request GET: QUERY_STRING: %s" % qs)

                if d is not None:
                    if "emailaddress" in d:
                        emailaddress = d["emailaddress"][0]
                        emailaddress.strip()
                        if '@' not in emailaddress:
                            emailaddress = unquote(emailaddress)
                        status = STAT_OK
                        schema = "autoconfig"
                    else:
                        logging.warning("Error in autoconfig request!")
                        process = False
                        status = STAT_ERR
                else:
                    logging.error("Request GET: QUERY_STRING failed!")
                    process = False
                    status = STAT_ERR

    if process:
        if data.debug:
            logging.debug("Entering data.configure()")
        try:
            if data.memcache.allow_client():
                data.configure(emailaddress, cn, password)
            else:
                process = False
                status = STAT_ERR
                logging.warning("Request %d [%s] blocked!"
                                % (data.memcache.counter(),
                                   environ["REMOTE_ADDR"]))
        except DataNotFoundException:
            process = False
            status = STAT_ERR
            data.memcache.set_client()
            logging.warning("Request %d [%s]" % (data.memcache.counter(),
                                                 environ["REMOTE_ADDR"]))
        except Exception as e:
            if data.debug:
                tb = traceback.format_exc()
                logging.error(tb)
            else:
                logging.error("data.configure(): %s" % e)
            process = False
            status = STAT_ERR

    if process:
        if data.debug:
            logging.debug("Entering view()")
        try:
            view = View(data, schema, subschema)
            response_body = view.render()
            if len(response_body) == 0:
                status = STAT_ERR
        except Exception as e:
            if data.debug:
                tb = traceback.format_exc()
                logging.error(tb)
            else:
                logging.error("view.render(): %s" % e)
            status = STAT_ERR

    if process:
        if data.debug:
            if (schema == "mobileconfig" and
                    "sign_mobileconfig" in data.domain and
                    data.domain["sign_mobileconfig"] is True):
                logging.debug("No debugging output for signed mobileconfig!")
            else:
                if sys.version_info < (3,):
                    logging.debug("Response:\n" + response_body.decode('utf-8'))
                else:
                    logging.debug(str("Response:\n%s" % response_body))

    body_len = str(len(response_body))

    def aenc(key, value):
        """Auto-enocde to ascii; Make headers compatible for Py2/Py3

        :param key: header key
        :param value: header value
        :return: auto encoded tuple
        """
        if sys.version_info < (3,):
            return key.encode("ascii"), value.encode("ascii")
        else:
            return key, value

    if schema in ('autoconfig', "autodiscover"):
        response_headers = [aenc('Content-Type', 'text/xml'),
                            aenc('Content-Length', body_len)]
    elif schema == "mobileconfig":
        response_headers = [aenc('Content-Type',
                                 'application/x-apple-aspen-config'
                                 '; charset=utf-8'),
                            aenc('Content-Disposition',
                                 'attachment; '
                                 'filename="company.mobileconfig'),
                            aenc('Content-Length', body_len)]
    else:
        # Failure?
        response_headers = [aenc('Content-Type', 'text/html'),
                            aenc('Content-Length', body_len)]

    if sys.version_info < (3,):
        status = status.encode("ascii")

    start_response(status, response_headers)

    return [response_body]

# vim: expandtab ts=4 sw=4
