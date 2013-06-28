#!/usr/bin/perl

use Cwd;

my $builddir = getcwd;
my @test_files = <$builddir/t/*.t>;

foreach $file (@test_files) {
	print "-------------------------------------- begin ----------------------------------\n";
	print "file: $file\n";
	&test($file);
	print "--------------------------------------- end -----------------------------------\n";
}

sub test {
	my ($file) = @_;
	my $childpid = fork();

	unless ($childpid) {
		exec "perl $file";
		exit;
	}
	
	waitpid($childpid, 0);
}
