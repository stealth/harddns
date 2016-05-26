harddns nss module
==================

aka Hardy Mc Hardns NSS module for using Google DNS over HTTPS in your system
resolving (for Linux).

Build
-----

The build requires openssl libraries to be installed. Then just

```
$ make
```

to create the `libnss_harddns.so` NSS module

Install
-------

Copy the nss `libnss_harddns.so` file to `/lib64/libnss_harddns.so.2` (`/lib` on 32Bit systems) and make sure
its owned by root:root and has mode 0755.
Copy the `samples` directory to `/etc/harddns` and make sure it has proper ownership
and permissions either.

Harddns already comes with a pinned Google X509 certificate that is matched upon
setup of the TLS connection. In case its expired, you can obtain one by yourself:
(using the first certificate B64 blob in the chain)

```
$ openssl s_client -showcerts -connect dns.google.com:443
```

You may put any number of pinned certificates to the `pinned` subdir. The filename
has to end with `.pem`. At least one of the certificates inside this directory has to match
upon the TLS connect.

I just included it for convenience. You may also use IP or IP6 addresses for `dns.google.com`
that you found out yourself. Its just a list that worked for me.

Once the config and nss module is in place, stop _nscd_ if it is running, and add the harddns
module to your `/etc/nsswitch.conf` file, so it looks like so or similar:

```
[...]
hosts:          files harddns mdns_minimal [NOTFOUND=return] dns
[...]
```

That tells your _glibc_ to use _harddns_ before _mdns_ and _dns_. If you want to kick out
resolve by UDP completely, remove the _mdns_ and _dns_ specification.

Start _nscd_ again, if it has been running before, and you are done. All __gethostbyname()__,
__getaddrinfo()__ etc. calls will now be handled by harddns. You can also watch it
in action by viewing the system log files, if `log_requests` has been specified.

Notes
-----

Hardy Mc Hardns is using the official [DNS-over-HTTPS API provided by Google](https://developers.google.com/speed/public-dns/docs/dns-over-https)

The content of the pinned certificate can be viewed via

```
$ openssl x509 -text < /etc/harddns/pinned/dns1.pem
```

Code is experimental. Maybe I should add some tor glue code in future, to overcome the
inherent DNS lookup problem. Note that browsers like chrome run their own integrated resolver
libs and will not use the system resolver.


