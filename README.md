harddns nss module
==================

aka Hardy Mc Hardns NSS module for using public DoH (DNS over HTTPS) in your system
resolving (for Linux).

Build
-----

The build requires openssl libraries to be installed. Then just

```
harddns $ make
[...]
```

to create the `libnss_harddns.so` NSS module

Install
-------

The install script will overwrite any existing previous *harddns* config and
comes with quite some public DoH servers pre-configured.

As root, do:
```
harddns # ./install.pl
[*] Installing config to /etc/harddns/harddns.conf
[*] Installing lib to /lib/x86_64-linux-gnu/libnss_harddns.so

Success so far. To enable DoH resolving system-wide, add
harddns to your /etc/nsswitch.conf file in the 'hosts' line.

[...]
hosts:          files harddns [NOTFOUND=return] dns [...]
[...]
harddns #
```

If you have any (legacy) pinned certificates inside `/etc/harddns/pinned`,
you should remove them. *harddns* is now using the CA bundle of your system.

Only place PEM files inside the `pinned` subdir if you know what you are doing.

If you need to:
```
$ openssl s_client -showcerts -connect 1.1.1.1:443
```

will give you the required certificates.

You may put any number of pinned certificates to the `pinned` subdir. The filename
has to end with `.pem`. At least one of the certificates inside this directory has to match
during the TLS connect, otherwise the resolve will fail.

Once the config and nss module is in place, stop _nscd_ if it is running, and add the
*harddns* module to your `/etc/nsswitch.conf` file, so it looks like this or similar:

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

Hardy Mc Hardns is using the official [DNS-over-HTTPS API provided by Google](https://developers.google.com/speed/public-dns/docs/dns-over-https), *Cloudlflare* and *Quad9*.

The content of the pinned certificate can be viewed via

```
$ openssl x509 -text < /etc/harddns/pinned/dns1.pem
```

