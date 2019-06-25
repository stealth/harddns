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

to create the `libnss_harddns.so` NSS module. Since usability of DoH benefits
a lot from low latency, you should consider using TLS 1.3 along with TCP Fast Open
for a quicker TLS handshake. *harddns* already enables TCP Fast Open by itself
as long as you have Linux kernel >= 4.11 and enabled it in /proc:

```
harddns $ cat /proc/sys/net/ipv4/tcp_fastopen
1
harddns $
```

where `1` means that it is enabled on client side, which is the default.
The `Makefile` is alredy set up to be used with custom *OpenSSL* installs,
as most vendors most likely do not ship *OpenSSL 1.1.1* yet, which is the
minimum version required to use TLS 1.3.
*harddns* may be used without all that fine tuning, however you could cut
latency in half if you do.


Install
-------

The install script will overwrite any existing previous *harddns* config and
comes with quite some public DoH servers pre-configured.

As root, do:
```
harddns # make install
./install.pl
[*] Installing config to /etc/harddns/harddns.conf
[*] Installing lib to /lib/x86_64-linux-gnu/libnss_harddns.so
```

Success so far. To enable DoH resolving system-wide, stop *nscd*
and add harddns to your `/etc/nsswitch.conf` file in the 'hosts' line.

```
[...]
hosts:          files harddns [NOTFOUND=return] dns [...]
[...]
harddns #
```

If you have any (legacy) pinned certificates inside `/etc/harddns/pinned`,
you should remove them. *harddns* is now using the CA bundle of your system.

Only place PEM files inside the `pinned` subdir if you know what you are doing.

If you really need pinned certifcates:
```
$ openssl s_client -showcerts -connect 1.1.1.1:443
```

will give you the required certificates.

You may put any number of pinned certificates to the `pinned` subdir. The filename
has to end with `.pem`. At least one of the certificates inside this directory has to match
during the TLS connect, otherwise the resolve will fail.

Start *nscd* again, if it has been running before, and you are done. All `gethostbyname()`,
`getaddrinfo()` etc. calls will now be handled by *harddns*. You can also watch it
in action by viewing the system log files, if `log_requests` has been specified.

AppArmor/SELinux
----------------

If your system is using confinement/MAC, make sure you add apropriate rules
for the confined programs to allow reading of `/etc/harddns/harddns.conf`.

For example, `/etc/apparmor.d/usr.sbin.nscd` should contain a line like

```
/etc/harddns/harddns.conf r,

```

in your *AppArmor* config.

Notes
-----

Hardy Mc Hardns is using the official [DNS-over-HTTPS API provided by Google](https://developers.google.com/speed/public-dns/docs/dns-over-https), *Cloudlflare* and *Quad9* servers. The *Cloudflare* DNS servers are listed in the config first,
because they use TLS 1.3 and TCP Fast Open and have good latency.

The content of the pinned certificate can be viewed via

```
$ openssl x509 -text < /etc/harddns/pinned/dns1.pem
```

