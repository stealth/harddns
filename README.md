D'oH! harddns
=============

![harddns](https://github.com/stealth/harddns/blob/master/logo.jpg)

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9MVF8BRMX2CWA)

*harddns* was one of the first DoH implementations for Linux
at a time when only one big search company offered a public
`dns-json` API endpoint in 2016 and there have not been any RFCs
about it. It began as a Name Service Switch (NSS) module.
Since then it has evolved and currently features:

* NSS module for Linux
* non-NSS, standalone proxy daemon, if desired
* Linux, BSD and OSX support
* RFC8484 and RFC8427 support
* caching of successful resolves
* TCP Fast Open when OS supports it
* TLS 1.3 ready to benefit from faster handshakes (0-RTT)
* Enterprise ready: can handle internal and external domains differently
* small footprint and least privilege design
* batteries included: comes with a config that works with all major DoH providers

As always, if you like the project, please give it a github star. Github stars are
valuable for developers' CV's and reputation in open source communities.


Build
=====

Linux
------

The build requires openssl libraries to be installed. Then just

```
harddns $ make
[...]
```

to create the `libnss_harddns.so` NSS module and proxy. Since usability of DoH benefits
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

OSX
---

The build requires the GNU toolchain and openssl libraries installed.
You then need to change the ssl library path to match your install
inside `src/Makefile`.

```
harddns $ make
[...]
```

BSD
---

On BSD systems you need `gmake` (gnu-make) installed.

```
harddns $ gmake -C src
[...]
```

This will give you the *harddnsd* daemon for installation.


Install
-------

The install script will overwrite any existing previous *harddns* config and
comes with quite some public DoH servers pre-configured.

As root, do:
```
harddns # make install
perl ./install.pl
[*] Installing config to /etc/harddns/harddns.conf
[*] Installing lib to /lib/x86_64-linux-gnu/libnss_harddns.so
[*] Installing proxy daemon to /usr/local/bin/harddnsd

Success so far. To enable DoH resolving system-wide, add
either harddns to your /etc/nsswitch.conf file in the 'hosts' line:

[...]
hosts:          files harddns [NOTFOUND=return] dns [...]
[...]


If you are using AppArmor or SELinux, you need to review/adjust your
profiles/policies (check README). Then restart nscd to take effect.


If you do not want or cannot use the NSS approach, you may ignore
above hints. Then you may just start /usr/local/bin/harddnsd
and change your resolver config to point to "127.0.0.1".
Then change your system startup scripts to start harddnsd automatically
at boot.

```

And follow the instructions for the `nsswitch.conf` modification or
the proxy-daemon startup at your choice. The recommended usage is
via the *harddnsd* daemon.

If you have any (legacy) pinned certificates inside `/etc/harddns/pinned`,
you should remove them. *harddns* is now using the CA bundle of your system.
It's strongly discouraged to use pinned certificates, as DoH endpoint certificates
change often.

Only place PEM files inside the `pinned` subdir if you know what you are doing.

If you really need pinned certifcates:
```
$ openssl s_client -showcerts -connect 1.1.1.1:443
```

will give you the required certificates.

You may put any number of pinned certificates to the `pinned` subdir. The filename
has to end with `.pem`. At least one of the certificates inside this directory has to match
during the TLS connect, otherwise the resolve will fail.

Restart *nscd*, if it was running, and you are done. All `gethostbyname()`,
`getaddrinfo()` etc. calls will now be handled by *harddns*. You can also watch it
in action by viewing the system log files, if `log_requests` has been specified.
If you have IPv6 connectivity and use the NSS module, you should enable
`nss_aaaa` in `/etc/harddns/harddns.conf` in order to lookup AAAA records too.

If your OS does not support NSS, just start

```
harddns # /usr/local/bin/harddnsd

harddns -- DoH proxy server v0.53 (C) 2019 Sebastian Krahmer https://github.com/stealth/harddns


Starting up DoH proxy at 127.0.0.1:53 change with [-l addr] [-p port]
switching to user 'nobody' (change with [-u user])

harddns #
```

and add `127.0.0.1` in your `/etc/resolv.conf`, or for OSX use:

```
harddns # networksetup -setdnsservers "Ethernet" 127.0.0.1 the.other.one
```

```
harddns # cat /etc/resolv.conf

nameserver 127.0.0.1
nameserver the.other.one

```

Note that *harddnsd* is marked as first DNS resolver, but you still
keep the one that you used before, as *harddnsd* proxy is currently just
resolving A and AAAA records. Some programs, such as *FreeBSD*'s
`pkg` however make strange requests to find update servers, which
*harddnsd* can't handle. So the second entry is the fallback for
these cases. Support for non-A/AAAA requests may be added later. If you run
`systemd-resolv` or `dnsmasq` on `127.0.0.1:53` you may use `127.0.0.2`
as binding address for *harddnsd* and use it in `/etc/resolv.conf`
accordingly, so you do not need to remove your existing configs if you
just want to test it.


You have to create your own startup scripts if you want to start *harddnsd* at boot.

Make sure that your firewalling rules allow DNS traffic on loopback and outgoing https
traffic to the dedicated DoH servers.

On some BSD systems, such as *NetBSD*, you need to install the openssl
root CA's by hand, before *harddnsd* can be started:

```
bsd # pkgin install mozilla-rootcerts
[...]
bsd # mozilla-rootcerts install
```


AppArmor/SELinux
----------------

If your system is using confinement/MAC, make sure you add apropriate rules
for the confined programs to allow reading of `/etc/harddns/harddns.conf`.

For example, `/etc/apparmor.d/usr.sbin.nscd` should contain a line like

```
/etc/harddns/harddns.conf r,

```

in your *AppArmor* config.


Enterprise setups
-----------------

It may happen that you want to have DoH for most of your lookups, but need to excempt
certain domains from DoH and need to contact a normal DNS server instead.
This may be configured as follows:

```
internal_domain = company.lan, 192.168.0.1
internal_domain = partner.lan, 10.0.0.1
```

Rather than contacting public DoH servers for the domains `company.lan` and
`partner.lan`, this would proxy the DNS requests as is to `192.168.0.1` and
`10.0.0.1` respectively. All other domain lookups are still directed to
the DoH servers as configured.
This requires that you start *harddnsd* (rather than using the NSS module)
and bind it to an IP address different from localhost, because it needs
to forward the DNS answers as coming back on the LAN interface.


Safety considerations
---------------------

You should run *harddnsd* either on the loopback interface or bind it
to an address via `-l` that is part of the private IP space and does
not belong to the globally routable IP space. *harddnsd* tries to detect this
and warn you, if you avoid this recommendation. If you ignore this warning
its not the end of the world but in this case everybody could abuse you
as a recursive resolver and resolve arbitrary stuff masked as you.


Notes
-----

Harddns is using the official [DNS-over-HTTPS API provided by Google](https://developers.google.com/speed/public-dns/docs/dns-over-https), *Cloudlflare* and *Quad9* servers. The *Cloudflare* DNS servers are listed in the config first,
because they use TLS 1.3 and TCP Fast Open and have good latency.

The content of the pinned certificate can be viewed via

```
$ openssl x509 -text < /etc/harddns/pinned/dns1.pem
```


