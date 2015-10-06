=======
INSTALL
=======

This document contains step by step instructions to install automx.

automx Download
===============

If you haven't done so yet download automx from its website::
   
        $ wget http://automx.org/download/latest.tar.gz

Unpack the tar archive and change into the newly created directory::
   
        $ tar xzf latest.tar.gz
        $ cd automx-VERSION

Software Requirements
=====================

automx is a Python application. You must install a few extra modules to
handle frontend and backend communication as well to deal with XML
data.

frontend
        Install mod_wsgi for the Apache web server and the python-wsgi
        module.

backend (optional)
        If you plan to use either LDAP or SQL as backends to retrieve
        configuration options from install ldap for LDAP and
        python-sqlalchemy for SQL. Further you also need to install the
        SQL backend driver that communicates with your database. For
        MySQL this might be mysqldb.

XML handling
        Install the python-packages dateutil, ipaddr, lxml and memcache.
        Otherwise automx will not be able to handle the XML data it needs
        to deal with.

plist (mobileconfig) handling
        Mobileconfig profiles may be signed with your webservers cert and
        key. You need to install M2Crypto, which does the S/MIME-signing.

Once you've satisfied the requirements, you can start to install automx.

   
Installing automx
=================

automx is a wsgi script depending on some automx-specific libraries. It
reads its configuration from a single configuration file. The program,
the libraries and the configuration file need to be installed at
different locations.

   
Installing the program
''''''''''''''''''''''

Create a directory for the automx program and copy it to that location::
   
        $ mkdir -p /usr/local/lib/automx
        $ cp automx-VERSION/src/automx_wsgi.py /usr/local/lib/automx/


Installing the test program
'''''''''''''''''''''''''''

Copy the automx-test program to a location that is in your $PATH::
   
        $ cp automx-VERSION/src/automx-test /usr/local/bin/automx-test


Installing automx-specific libraries
''''''''''''''''''''''''''''''''''''

Python loads packages from various locations depending on your
distribution and python version. To correctly determine the used
paths please type the following commands::

        $ python
        >>> import sys
        >>> sys.path
        >>> (CTRL+D)
   
You'll get a list of used paths. Please remember the first shown path
entry (for example '/usr/lib/python2.7') -  this is the best location for
placing the automx-directory::
   
        $ cp -r automx-VERSION/src/automx /usr/lib/pythonVERSION

 
Installing man Pages
''''''''''''''''''''

Try using the manpath command to find out where man pages are stored on
your computer::
   
        $ manpath /usr/local/man:/usr/local/share/man:/usr/share/man

Copy the man pages to that location::
   
        $ cp -a automx-VERSION/doc/man/ /usr/local/share/man


Installing the configuration file
'''''''''''''''''''''''''''''''''

Place the sample automx.conf file into /etc::
   
        $ cp automx-VERSION/src/conf/automx.conf /etc/

Follow automx.conf(5) Adopt this configuration file to your needs. You
may find detailed information in the man page automx.conf(5).

Tip

Set debug=yes in the section automx while you setup, configure and test
automx. It will help you detect problems more easily. This will log the
request GET/POST and the response to the error.log file(s).

   
DNS Configuration
=================

Mail clients seeking mail account autoconfiguration will either request
an IP address for autoconfig.example.com (Mozilla schema) or
autodiscover.example.com (Microsoft schema). Provide settings in your
DNS that directs them to the server running the automx service::

        autoconfig.example.com.              IN    A     192.168.2.1
        autodiscover.example.com.            IN    A     192.168.2.1

.. NOTE::

        If you install automx on an existing host, which has it's own
        domain-name, then it is also possible to use above entries as
        nicknames:

        somehost.example.com.       IN      A       192.168.2.1
            autoconfig              IN      CNAME   somehost
            autodiscover            IN      CNAME   somehost
   
   
Web Server Configuration
========================

Finally configure the web server. It will accept configuration requests
from mail clients, pass the information to automx and in turn will
respond with account profiles once automx has figured out the details.

First enable the wsgi module. Follow your OS documentation to find out
how it needs to be done. (e.g. 'a2enmod wsgi' for Apache on Debian)

automx is able to provision mail clients following the Mozilla
autoconfig schema as well as mail clients following the Microsoft
autodiscover schema. Both schemas have different requirements regarding
hostname, port and level of security when a request is sent to the
configuration server:

Microsoft
        Mail clients following the Microsoft autodiscover schema require
        a https connection. The web server must identify itself as
        autodiscover.example.com on port 443 and it must use a valid
        server certificate that is trusted by the mail client requesting
        configuration.

Mozilla
        Mail clients following the Mozilla autoconfig schema can use
        either a http or a https connection. The web server must
        identify itself as autoconfig.example.com on port 80 or 443. If
        it connects on 443 a valid server certificate that is trusted by
        the mail client requesting configuration has to be used.

To provision Apple iOS devices or Mac OS X Mail, you need to place the file
automx.html somewhere in your document root of your webserver. After that
you can use your iOS device and open the Safari browser calling this
website. After entering the form data, you will receive a mobileconfig
file and the device switches to the settings assistent. On Mac OS X, you
also can call this document and save it to disk. After opening it, the
profile manager opens and the steps are similar to iOS. For signed
profiles see the man page automx.conf(5).

Here is a simple example that configures an autoconfig and an
autodiscover service (both use the same automx script). You need
to copy & paste this lines into your existing website configuration
files (for Debian take a look in /etc/apache2/sites-enabled/...)::

        <VirtualHost *:80>
                ServerName example.com
                ServerAlias autoconfig.example.com
                ServerAdmin webmaster@example.com
                <IfModule mod_wsgi.c>
                        WSGIScriptAliasMatch \
                                (?i)^/.+/(autodiscover|config-v1.1).xml \
                                /usr/lib/automx/automx_wsgi.py
                        <Directory "/usr/lib/automx">
                                Order allow,deny
                                Allow from all
                        </Directory>
                </IfModule>
        </VirtualHost>

        <VirtualHost *:443>
                ServerName example.com:443
                ServerAlias autodiscover.example.com:443
                ServerAdmin webmaster@example.com
                <IfModule mod_wsgi.c>
                        WSGIScriptAliasMatch \
                                (?i)^/.+/(autodiscover|config-v1.1).xml \
                                /usr/lib/automx/automx_wsgi.py
                        WSGIScriptAlias \
                                /mobileconfig \
                                /usr/lib/automx/automx_wsgi.py
                        <Directory "/usr/lib/automx">
                                Order allow,deny
                                Allow from all
                        </Directory>
                </IfModule>
        </VirtualHost>

.. NOTE::

        If you haven't done so, you also need to configure and enable SSL in
        your apache-configuration. At least that means enabling the default
        SSL-site, install (self signed) certificates and activating the
        ssl-support (e.g. 'a2enmod ssl' for Apache on debian). Don't forget to
        restart your web-server afterwards! You need also to ajust the paths
        to automx_wsgi.py in the example above.

.. NOTE::
For Nginx see the example configuration file nginx-automx.conf. You
        can place this file into /etc/nginx/conf.d (this depends on your
        distribution) and adopt it to your needs.

.. NOTE:: ISPs

        In an advanced environment with thousands of domains, you can redirect
        mail clients via DNS entries to your ISP automx provisioning server for
        Microsoft clients and a web server instance with a wild card ServerName
        to serve the Mozilla schema.
        
        Add this to your DNS-configuation:

        \*.example.com.        A     192.168.2.1

and this to your virtualhost-definition in your webserver-configuration::
        
        ServerAlias *.example.com

automx comes with a little utility that helps testing proper operation.
The next section explains how to use it.


Testing And Debugging automx
============================

The automx-test utility sends configuration requests for Microsoft and
Mozilla clients to the web server::

        $ automx-test user@example.com

The domainpart in the address determines the list of hostnames that
will be queried. In this example autoconfig.example.com and
autodiscover.example.com will be contacted.

You should see the web server header. The script will say Success or
Failed.

If things go wrong, the error.log is your friend. It will indicate
configuration issues, if python modules are missing, if your database
can not be queried or anything else that might go wrong. If you also
enabled debug in /etc/automx.conf, you will find further information
in your automx.log file. Please turn on debug, if you want to send us
a bug report. PLEASE NOTICE! Mobileconfig will display a users password
in cleartext! So please remove that from bug reports first!

   
.. NOTE::

        If you split error logs by port, e.g. port 80 and 443, you need to
        check both. Autoconfig requests will mostly show up in the port 80
        error.log, whereas autodiscover will only show up in your 443
        error.log.

   
Authors
'''''''

Christian Roessner <cr@sys4.de>
        Wrote the program.

Patrick Ben Koetter <p@sys4.de>
        Wrote the documentation.

Christian Sudec <c.sudec@htlwrn.ac.at>
        04-22-2013: Updated the documentation to support automx 0.9.2
