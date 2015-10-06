=============
 automx_sql
=============

:Date: 02/08/2013
:Subtitle: automx SQL backend configuration parameters
:Manual Section: 5
:Manual Group: automx
:Copyright: This document has been placed in the public domain.


Description
'''''''''''

The automx_sql(5) man page specifies all parameters that control access from within automx to a SQL backend.

Parameters
''''''''''

host (default: none)
	Specifies one or more SQL servers separated by commas. Each server specification must provide database driver, username and password to access a database on a host as shown in the following example::

		host = driver://username:password@hostname/database

	.. IMPORTANT::

		Subsequent servers to the first serve only for fallback purposes, i.e. a server to the right will only be queried if the server left to it cannot be reached. If a server can be reached no further attempts will be made regardless if the query returned a result or not.

query (default: none)
	Specifies the query that should be sent to the database specified with the host parameter:

		query = SELECT displayname, mailaddr FROM mail WHERE mailaddr='%s';

	.. NOTE::

		See the section called “Macros and Variables” in automx.conf(5) for a list of available query macros.

result_attrs (default: none)
	Specifies the attributes whose values should be used in an automx account setup:

		result_attrs = displayname, mailaddr

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
