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

import traceback

from cgi import escape
from urlparse import parse_qs
from cStringIO import StringIO
from lxml import etree
from lxml.etree import XMLSyntaxError

from automx.config import Config
from automx.view import View


def application(environ, start_response):
    debug = False
    
    response_body = ""
    emailaddress = ""
    
    # schema currently may be  'autoconfig' or 'autodiscover'
    schema = None

    # subschema currently is either 'mobile' or 'outlook'
    subschema = None
        
    data = Config()
    
    try:
        if data.has_option("automx", "debug"):
            debug = data.getboolean("automx", "debug")
    except:
        pass
        
    request_method = environ['REQUEST_METHOD']
    request_method = escape(request_method)

    process = True
    
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
    
            if debug:
                debug_msg = etree.tostring(root,
                                           xml_declaration=True,
                                           method="xml",
                                           encoding="utf-8",
                                           pretty_print=True)
                print >> environ['wsgi.errors'], ("debug, request POST\n" +
                                                  debug_msg) 
    
            # We need to strip the namespace for XPath
            expr = "//*[local-name() = $name]"
    
            response_schema = root.xpath(expr,
                                         name="AcceptableResponseSchema")
            if len(response_schema) == 0:
                print >> environ['wsgi.errors'], "Error in XML request"
            else:
                # element.text is a http-URI that has a location part which we
                # need to scan.
                if "/mobilesync/" in response_schema[0].text:
                    subschema = "mobile"
                elif "/outlook/" in response_schema[0].text:
                    subschema = "outlook"
    
                emailaddresses = root.xpath(expr, name="EMailAddress")
                if len(emailaddresses) == 0:
                    print >> environ['wsgi.errors'], "Error in XML request"
                else:
                    emailaddress = emailaddresses[0].text
                    schema = "autodiscover"
            
            status = "200 OK"

        else:
            process = False
            status = "500 Internal Server Error"

    elif request_method == "GET":
        # FIXME: maybe we need to catch AutoDiscover GET-REDIRECT requests
        if "autodiscover" in (environ["HTTP_HOST"],
                              environ["REQUEST_URI"].lower()):
            process = False
            status = "500 Internal Server Error"
        
        # autoconfig
        else:            
            d = parse_qs(environ['QUERY_STRING'])
        
            emailaddress = d.get('emailaddress', [''])[0]
            if emailaddress is None:
                status = "500 OK"
            else:
                schema = "autoconfig"
                
            if debug:
                print >> environ['wsgi.errors'], ("debug, request GET: "
                                                  "QUERY_STRING=%s" % d)

            status = "200 OK"

    if process:
        try:
            data.configure(environ, emailaddress)
            if len(data.domain) == 0:
                # Something went wrong
                process = False
                status = "500 Internal Server Error"
        except Exception, e:
            if debug:
                tb = traceback.format_exc()
                print >> environ['wsgi.errors'], tb
            else:
                print >> environ['wsgi.errors'], "data.configure(): %s" % e
            status = "500 Internal Server Error"
    
    if process:
        try:
            view = View(data, schema, subschema)
            response_body = view.render()
        except Exception, e:
            if debug:
                tb = traceback.format_exc()
                print >> environ['wsgi.errors'], tb
            else:
                print >> environ['wsgi.errors'], "view.render(): %s" % e
            status = "500 Internal Server Error"

    if debug:
        print >> environ['wsgi.errors'], "debug, response:\n" + response_body

    response_headers = [('Content-Type', 'text/xml'),
                        ('Content-Length', str(len(response_body)))]
    start_response(status, response_headers)

    return [response_body]
