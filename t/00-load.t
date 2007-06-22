#!perl -T

use Test::More tests => 2;

BEGIN {
	use_ok( 'Digest::MD5::Reverse' );
}

diag( "Testing Digest::MD5::Reverse $Digest::MD5::Reverse::VERSION, Perl $], $^X" );
use Digest::MD5::Reverse qw(reverse_md5);
my $data = reverse_md5('acbd18db4cc2f85cedef654fccc4a4d8');
is($data, 'foo', 'correct');
