=============
 automx_ldap
=============                                                                                                                                          

:Date: 02/08/2013
:Subtitle: automx LDAP backend configuration parameters
:Manual Section: 5
:Manual Group: automx
:Copyright: This document has been placed in the public domain.


Description
'''''''''''

The automx_ldap(5) man page specifies all parameters that control access from
within automx to a LDAP backend.

Parameters
''''''''''

authzid (no default)
	Specifies the SASL proxy authorization identity.

base (default: none)
	Specifies the default base DN to use when performing ldap operations. The base must be specified as a Distinguished Name in LDAP format.

binddn (default: none)
	Specifies the default bind DN to use when performing ldap operations. The bind DN must be specified as a Distinguished Name in LDAP format.

bindmethod (default: simple)
	Specifies how authentication should take place. Valid options are either simple for a simple bind or sasl for a bind that requires SASL authentication.

bindpw (default: none)
	Specifies the password used when binddn identifies itself with the LDAP server.

cacert (default: none)
	Specifies the path to a file that contains all certificates of Certification Authorities automx should trust.

cert (default: none)
	Specifies the path to a file that contains automx's certificate.

cipher (default: TLSv1)
	See ciphers(1) for a list of valid options.

filter (default: (objectClass=*))
	Specifies the search filter to select appropriate LDAP objects. The filter should conform to the string representation for search filters as defined in RFC 4515.

	.. NOTE::

		See the section “Macros and Variables” in automx.conf(5) for a list of available query macros.

host (default: ldap://127.0.0.1/)
	Specifies one or more LDAP servers separated by commas as shown in the following example::

		host = ldap://127.0.0.1, ldap://192.168.2.1

	.. IMPORTANT::

		Subsequent servers to the first serve only for fallback purposes, i.e. a server to the right will only be queried if the server left to it cannot be reached. If a server can be reached no further attempts will be made regardless if the query returned a result or not.

key (default: none)
	Specifies the path to a file that contains automx's private key, which matches automx certificate given with cert.

reqcert (default: never)
	Specifies what checks to perform on server certificates in a TLS session, if any. The <level> can be specified as one of the following keywords:

        never
		The client will not request or check any server certificate. This is the default setting.

        allow
                The server certificate is requested. If no certificate is provided, the session proceeds normally. If a bad certificate is provided, it will be ignored and the session proceeds normally.

        try
                The server certificate is requested. If no certificate is provided, the session proceeds normally. If a bad certificate is provided, the session is immediately terminated.

        demand
                These keywords are equivalent. The server certificate is requested. If no certificate is provided, or a bad certificate is provided, the session is immediately terminated.

result_attrs (default: none)
	If automx finds one or more entries, the attributes specified by result_attrs are returned. If * is listed, all user attributes are returned.

saslmech (default: none)
	Specifies the SASL mechanism to be used for authentication.

        cram-md5
                The SASL cram-md5 mechanism (see: RFC 2195) will be used to authenticate LDAP bind requests.

        digest-md5
                The SASL digest-md5 mechanism (see: RFC 2831) will be used to authenticate LDAP bind requests.

        external
                The SASL external mechanism (see: RFC 4422) will be used to authenticate LDAP bind requests.

        gssapi
                The SASL gssapi mechanism (see: RFC 4752) will be used to authenticate LDAP bind requests.

        none
                No SASL mechanism will be use to authenticate LDAP bind requests.

scope (default: sub)
	Specify the scope of the search to be one of base (or exact), one (or onelevel), sub (or substree), to specify a base object, one-level, or subtree search.

usetls (default: false)
	Specifies if automx should use TLS when it connects to the LDAP host.

Authors
'''''''

Christian Roessner <cr@sys4.de>
        Wrote the program.

Patrick Ben Koetter <p@sys4.de>
        Wrote the documentation.

See also
''''''''

`automx(8)`_, `automx.conf(5)`_, `automx_ldap(5)`_, `automx_script(5)`_, `automx_sql(5)`_, `automx-test(1)`_

.. _automx(8): automx.8.html
.. _automx.conf(5): automx.conf.5.html
.. _automx_ldap(5): automx_ldap.5.html
.. _automx_sql(5): automx_sql.5.html
.. _automx_script(5): automx_script.5.html
.. _automx-test(1): automx-test.1.html
