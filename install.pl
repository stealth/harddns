#!/usr/bin/perl -w


sub install_cfg
{
	my $tgt_cfg = "/etc/harddns/harddns.conf";
	my $src_cfg = "sample/harddns.conf";

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

	$tgt_lib .= $src_lib;

	print "[*] Installing lib to ${tgt_lib}\n";

	system("cp", "-f", $src_lib, $tgt_lib);
	chown(0, 0, $tgt_lib);
	chmod(0644, $tgt_lib);

	symlink($tgt_lib, $tgt_lib.".2");
}


sub print_cfg
{
print<<EOM;

Success so far. To enable DoH resolving system-wide, add
harddns to your /etc/nsswitch.conf file in the 'hosts' line.

[...]
hosts:          files harddns [NOTFOUND=return] dns [...]
[...]

EOM
}


umask(0);
install_cfg();
install_lib();
print_cfg();

