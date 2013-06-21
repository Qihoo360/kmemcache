#!/usr/bin/perl

use strict;
use Test::More tests => 17;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

eval {
    my $server = start_kmemcache();
    ok($server, "started the server");
    stop_kmemcache();
};
is($@, '', 'Basic startup works');

eval {
    my $server = start_kmemcache("-l fooble");
    stop_kmemcache();
};
ok($@, "Died with illegal -l args");

eval {
    my $server = start_kmemcache("-l 127.0.0.1");
    stop_kmemcache();
};
is($@,'', "-l 127.0.0.1 works");

eval {
    my $server = start_kmemcache('-C');
    my $stats = mem_stats($server->sock, 'settings');
    is('no', $stats->{'cas_enabled'});
    stop_kmemcache();
};
is($@, '', "-C works");

eval {
    my $server = start_kmemcache('-b 8675');
    my $stats = mem_stats($server->sock, 'settings');
    is('8675', $stats->{'tcp_backlog'});
    stop_kmemcache();
};
is($@, '', "-b works");

foreach my $val ('auto', 'ascii') {
    eval {
        my $server = start_kmemcache("-B $val");
        my $stats = mem_stats($server->sock, 'settings');
        ok($stats->{'binding_protocol'} =~ /$val/, "$val works");
        stop_kmemcache();
    };
    is($@, '', "$val works");
}

# For the binary test, we just verify it starts since we don't have an easy bin client.
eval {
    my $server = start_kmemcache("-B binary");
    stop_kmemcache();
};
is($@, '', "binary works");

eval {
    my $server = start_kmemcache("-vv -B auto");
    stop_kmemcache();
};
is($@, '', "auto works");

eval {
    my $server = start_kmemcache("-vv -B ascii");
    stop_kmemcache();
};
is($@, '', "ascii works");


# For the binary test, we just verify it starts since we don't have an easy bin client.
eval {
    my $server = start_kmemcache("-vv -B binary");
    stop_kmemcache();
};
is($@, '', "binary works");


# Should blow up with something invalid.
eval {
    my $server = start_kmemcache("-B http");
    stop_kmemcache();
};
ok($@, "Died with illegal -B arg.");

# kmemcache not use '-t'
# Should not allow -t 0
#eval {
#    my $server = start_kmemcache("-t 0");
#    stop_kmemcache();
#};
#ok($@, "Died with illegal 0 thread count");
