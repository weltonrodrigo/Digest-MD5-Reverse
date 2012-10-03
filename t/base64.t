#!perl -T
#
use Test::More tests => 2;

my $string = 'admin';
my $base64 = 'ISMvKXpXpadDiUoOSoAfww';

my $error_msg = qr{Can't locate MIME/Base64\.pm in \@INC};

use Digest::MD5::Reverse 'reverse_md5_base64';

#Pretend there is no MIME::Base64 in @INC;
{
  local @INC = ();

  eval { reverse_md5_base64($base64) };
  is( $@ =~ /$error_msg/, 1, 'Should inform absence of MIME::Base64.');
}

SKIP:{

  eval {require MIME::Base64};
  skip 'MIME::Base64 not installed', 1 if $@;

  is( $string, reverse_md5_base64($base64), 'Reverse Base64 MD5');

};
