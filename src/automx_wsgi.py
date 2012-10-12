"""
automx - auto configuration service
Copyright (C) 2012  sys4 AG

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

__version__ = '0.9'
__author__ = "Christian Roessner, Patrick Ben Koetter"
__copyright__ = "Copyright (C) 2012  sys4 AG"

import traceback
import logging

from cgi import escape
from urlparse import parse_qs
from cStringIO import StringIO
from lxml import etree
from lxml.etree import XMLSyntaxError

from automx.config import Config, DataNotFoundException
from automx.view import View


def application(environ, start_response):
    # HTTP status codes
    STAT_OK = "200 OK"
    STAT_ERR = "500 Internal Server Error"

    response_body = ""
    emailaddress = None
    
    # schema currently may be  'autoconfig' or 'autodiscover'
    schema = None

    # subschema currently is either 'mobile' or 'outlook'
    subschema = None
    
    process = True

    try:
        data = Config(environ)
    except:
        process = False
        status = STAT_ERR
    
    try:
        logging.basicConfig(filename=data.logfile,
                            format='%(asctime)s %(levelname)s: %(message)s',
                            level=logging.DEBUG)
    except IOError, e:
        print >> environ["wsgi.errors"], e
  
    if process:
        request_method = environ['REQUEST_METHOD']
        request_method = escape(request_method)
    
        if request_method == "POST":
            valid_xml = True
    
            try:
                request_body_size = int(environ.get('CONTENT_LENGTH', 0))
            except ValueError:
                request_body_size = 0
        
            # When the method is POST the query string will be sent
            # in the HTTP request body which is passed by the WSGI server
            # in the file like wsgi.input environment variable.
            request_body = environ['wsgi.input'].read(request_body_size)
    
            fd = StringIO(request_body)
            try:
                tree = etree.parse(fd)
            except XMLSyntaxError:
                valid_xml = False
            
            if valid_xml:
                root = tree.getroot()
        
                if data.debug:
                    debug_msg = etree.tostring(root,
                                               xml_declaration=True,
                                               method="xml",
                                               encoding="utf-8",
                                               pretty_print=True)
                    logging.debug("Request POST\n" + debug_msg) 
        
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
        
                    emailaddresses = root.xpath(expr, name="EMailAddress")
                    if len(emailaddresses) == 0:
                        logging.warning("Error in XML request")
                        process = False
                        status = STAT_ERR
                        data.memcache.set_client()
                    else:
                        emailaddress = emailaddresses[0].text
                        schema = "autodiscover"
                
                status = STAT_OK
    
            else:
                process = False
                status = STAT_ERR
                data.memcache.set_client()
    
        elif request_method == "GET":
            # FIXME: maybe we need to catch AutoDiscover GET-REDIRECT requests
            if "autodiscover" in (environ["HTTP_HOST"],
                                  environ["REQUEST_URI"].lower()):
                process = False
                status = STAT_ERR
            
            # autoconfig
            else:
                qs = environ['QUERY_STRING']
                d = parse_qs(qs)
            
                emailaddress = d.get("emailaddress")[0]
                if emailaddress is None:
                    process = False
                    status = STAT_ERR
                else:
                    schema = "autoconfig"
                    
                if data.debug:
                    logging.debug("Request GET: QUERY_STRING: %s" % qs)
    
                status = STAT_OK

    if process:
        try:
            if data.memcache.allow_client():
                data.configure(emailaddress)
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
        except Exception, e:
            if data.debug:
                tb = traceback.format_exc()
                logging.error(tb)
            else:
                logging.error("data.configure(): %s" % e)
            process = False
            status = STAT_ERR
    
    if process:
        try:
            view = View(data, schema, subschema)
            response_body = view.render()
            if response_body == "":
                status = STAT_ERR
        except Exception, e:
            if data.debug:
                tb = traceback.format_exc()
                logging.error(tb)
            else:
                logging.error("view.render(): %s" % e)
            status = STAT_ERR

    if data.debug:
        logging.debug("Response:\n" + response_body)

    response_headers = [('Content-Type', 'text/xml'),
                        ('Content-Length', str(len(response_body)))]
    start_response(status, response_headers)

    return [response_body]
