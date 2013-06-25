#!/usr/bin/perl

use strict;
use Test::More tests => 7;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $server = start_kmemcache();
my $sock = $server->sock;

my $stats = mem_stats($sock, ' settings');

# Ensure default still works.
is($stats->{item_size_max}, 1024 * 1024);
$server->stop();

# Should die.
eval {
    $server = start_kmemcache('-I 1000');
};
ok($@ && $@ =~ m/^Failed/, "Shouldn't start with < 1k item max");

eval {
    $server = start_kmemcache('-I 256m');
};
ok($@ && $@ =~ m/^Failed/, "Shouldn't start with > 128m item max");

# Minimum.
my $server = start_kmemcache('-I 1024');
my $stats = mem_stats($server->sock, ' settings');
is($stats->{item_size_max}, 1024);
$server->stop();

# Reasonable but unreasonable.
my $server = start_kmemcache('-I 1049600');
my $stats = mem_stats($server->sock, ' settings');
is($stats->{item_size_max}, 1049600);
$server->stop();

# Suffix kilobytes.
my $server = start_kmemcache('-I 512k');
my $stats = mem_stats($server->sock, ' settings');
is($stats->{item_size_max}, 524288);
$server->stop();

# Suffix megabytes.
my $server = start_kmemcache('-I 32m');
my $stats = mem_stats($server->sock, ' settings');
is($stats->{item_size_max}, 33554432);
$server->stop();

