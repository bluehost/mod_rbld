mod_rbld
======

mod_rbld is an Apache access module that checks any remote IPv4 address that 
makes a request by querying RBLD, and then returning a forbidden response to 
the end user if RBLD says the IP is blacklisted.
