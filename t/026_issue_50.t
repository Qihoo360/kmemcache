#!/usr/bin/perl

use strict;
use Test::More tests => 1;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = start_kmemcache('-B binary');
my $sock = $server->sock;

$SIG{ALRM} = sub { die "alarm\n" };
alarm(2);
print $sock "Here's a bunch of garbage that doesn't look like the bin prot.";
my $rv = <$sock>;
ok(1, "Either the above worked and quit, or hung forever.");

stop_kmemcache();
