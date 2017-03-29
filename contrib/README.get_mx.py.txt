Thanks to: .webflow GmbH

On our mailserver it´s necessary that automx dynamically detects the MX-Record from the requested domain to return the perfect configuration.
I´ve build a small automx-script for this problem.

The script takes the first argument and detects the primary MX-Record.
The second argument is used as fallback if the MX detection gets an timeout or other exception.

You need the dnspython module for this script to run:

pip install dnspython
