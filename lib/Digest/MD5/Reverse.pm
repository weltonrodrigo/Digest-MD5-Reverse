package Digest::MD5::Reverse;

use warnings;
use strict;
use Socket;
use Exporter;

=head1 NAME

Digest::MD5::Reverse - MD5 Reverse Lookup

=cut

our $VERSION = "1.3";
our @ISA = qw(Exporter);
our @EXPORT = qw(&reverse_md5);


=head1 VERSION

Version 1.3

=head1 SYNOPSIS

    use Digest::MD5::Reverse;
    my $plaintext = reverse_md5($md5);    

=head1 DESCRIPTION

MD5 sums (see RFC 1321 - The MD5 Message-Digest Algorithm) are used as a one-way
hash of data. Due to the nature of the formula used, it is impossible to reverse
it.

This module provides functions to search several online MD5 hashes database and
return the results (or return undefined if no match found).

We are not breaking security. We are however making it easier to lookup the
source of a MD5 sum.

=head1 EXAMPLES

    use Digest::MD5::Reverse;
    print "Data is ".reverse_md5("acbd18db4cc2f85cedef654fccc4a4d8")."\n";    
    # Data is foo

=head1 DATABASE

=over 4

=item * md5.rednoize.com

=item * md5.gromweb.com

=item * tools.benramsey.com

=back

=cut

our $DATABASE = [
  {
        host => "md5.rednoize.com",
        path => "/?q=%value%&xml",
        meth => "GET",
        mreg => qr{<ResultString>(.+?)</ResultString>}x
  },
	{
        host => "md5.gromweb.com",
        path => "/query/%value%",
        meth => "GET",
        mreg => qr{(.+)}x
  },
  {
        host => "tools.benramsey.com",
        path => "/md5/md5.php?hash=%value%",
        meth => "GET",
        mreg => qr{<string><!\[CDATA\[(.+?)]]></string>}x
  }
];

my $get = sub
{
	my($url,$path) = @_;
	socket(my $socket, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "Socket Error : $!\n";
	connect($socket,sockaddr_in(80, inet_aton($url))) or die "Connect Error: $!\n";
	send($socket,"GET $path HTTP/1.1\015\012Host: $url\015\012User-Agent: Firefox\015\012Connection: Close\015\012\015\012",0);
	return do { local $/; <$socket> };
};

my $post = sub
{
	my($url,$path,$content) = @_;
	my $len = length $content;
	socket(my $socket, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "Socket Error : $!\n";
	connect($socket,sockaddr_in(80, inet_aton($url))) or die "Connect Error : $!\n";
	send($socket,"POST $path HTTP/1.1\015\012Host: $url\015\012User-Agent: Firefox\015\012Content-Type: application/x-www-form-urlencoded\015\012Connection: Close\015\012Content-Length: $len\015\012\015\012$content\015\012",0);
	return do { local $/; <$socket> };
};

my $reverseit = sub  
{
	my $md5 = shift;
	return undef if length $md5 != 32;	
	my($string,$page);
	SEARCH:
	for my $site (@{ $DATABASE }) 
	{
		my $host = $site->{host};
		my $path = $site->{path};
		my $meth = $site->{meth};
		my $mreg = $site->{mreg};        
		my $content = $site->{content};
        if($meth eq "POST")
        {
		$content =~ s/%value%/$md5/ig;
		$page = $post->($host,$path,$content);            
        }
        else
        {
		$path =~ s/%value%/$md5/ig;
		$page = $get->($host,$path);            
        }         
	next unless $page;
	last SEARCH if(($string) = $page =~ /$site->{mreg}/);
	}
	return $string ? $string : undef;
};

sub reverse_md5
{
	return $reverseit->(shift);	
}

=head1 SEE ALSO

L<Digest::MD5>

=head1 AUTHOR

Raoul-Gabriel Urma << blwood@skynet.be >>

=head1 COPYRIGHT & LICENSE

Copyright 2007 Raoul-Gabriel Urma, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
