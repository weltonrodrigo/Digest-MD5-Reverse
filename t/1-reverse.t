use Test::More tests => 2;
BEGIN { use_ok('Digest::MD5::Reverse') };

use Digest::MD5::Reverse qw(r_md5_hex);
my $data = r_md5_hex('6df23dc03f9b54cc38a0fc1483df6e21');
is($data, 'foobarbaz', 'correct');