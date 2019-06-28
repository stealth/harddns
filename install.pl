#!/usr/bin/perl -w


sub install_cfg
{
	my $tgt_cfg = "/etc/harddns/harddns.conf";
	my $src_cfg = "config/harddns.conf";

	print "[*] Installing config to ${tgt_cfg}\n";

	mkdir("/etc/harddns", 0755);

	system("cp", "-f", $src_cfg, $tgt_cfg);
	chown(0, 0, $tgt_cfg);
	chmod(0644, $tgt_cfg);
}


sub install_lib
{
	my $tgt_lib = "/lib64/";
	my $src_lib = "libnss_harddns.so";

	if (-e "/lib/x86_64-linux-gnu") {
		$tgt_lib = "/lib/x86_64-linux-gnu/";
	}

	if (!-e $tgt_lib) {
		print "[-] Skipping install of NSS module. OSX?\n";
		return;
	}

	$tgt_lib .= $src_lib;
	$src_lib = "src/build/${src_lib}";

	print "[*] Installing lib to ${tgt_lib}\n";

	system("cp", "-f", $src_lib, $tgt_lib);
	chown(0, 0, $tgt_lib);
	chmod(0644, $tgt_lib);

	symlink($tgt_lib, $tgt_lib.".2");
}


sub install_proxy
{
	my $tgt_bin = "/usr/local/bin/";
	my $src_bin = "harddnsd";

	$tgt_bin .= $src_bin;
	$src_bin = "src/build/${src_bin}";

	print "[*] Installing proxy daemon to ${tgt_bin}\n";

	system("cp", "-f", $src_bin, $tgt_bin);
	chown(0, 0, $tgt_bin);
	chmod(0750, $tgt_bin);
}


sub print_cfg
{
print<<EOM;

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

EOM
}


umask(0);
install_cfg();
install_lib();
install_proxy();
print_cfg();

