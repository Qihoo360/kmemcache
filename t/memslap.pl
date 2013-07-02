#!/usr/bin/perl

use Cwd;

my $usage = "Usage: memslap.pl host:port get/set prefix";

if (@ARGV != 3) {
	die $usage;
}

my ($server, $test, $prefix) = @ARGV;

printf("server=%s test=%s outputfix=%s\n", $server, $test, $prefix);

if ($test eq 'get') {
	for ($conn = 1000; $conn <= 10000; $conn += 1000) {
		memslap($conn, 1000);
	}
} elsif ($test eq 'set') {
	print "set set set";
	for ($conn = 1000; $conn <= 10000; $conn += 1000) {
		for ($num = 1000; $num <= 10000; $num += 1000) {
			memslap($conn, $num);
		}
	}
} else {
	die $usage;
}

sub memslap {
	my ($conn, $num) = @_;
	my ($file) = sprintf("%s_%s_%s_%s", $prefix, $test, $conn, $num);
	my ($args) = sprintf("--servers=%s --test=%s --concurrency=%s --execute-number=%s >%s 2>&1", $server, $test, $conn, $num, $file);

	my $childpid = fork();

	unless ($childpid) {
		exec "memslap $args";
		exit;
	}
	
	waitpid($childpid, 0);
}
