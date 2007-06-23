package Digest::MD5::Reverse;
use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORTER @EXPORT_OK $DATABASE);
use Socket;


our $VERSION = "1.2";
@EXPORT_OK = qw(reverse_md5);
@ISA= qw(Exporter);

$DATABASE = [
	{
		host => "milw0rm.com",
		path => "/cracker/search.php",
		meth => "POST",
		content => "hash=%value%&Submit=Submit",
		mreg => qr{
		<TR\sclass="submit">
                <TD\salign="middle"\snowrap="nowrap"\swidth=90>md5<\/TD>
                <TD\salign="middle"\snowrap="nowrap"\swidth=250>\w{32}<\/TD>
                <TD\salign="middle"\snowrap="nowrap"\swidth=90>(.+?)<\/TD>
                <TD\salign="middle"\snowrap="nowrap"\swidth=90>cracked<\/TD>
		<\/TR>
                }x
	}, 
	{
		host => "hashreverse.com",
		path => "/index.php?action=view",
		meth => "POST",
		content => "hash=%value%&Submit2=Search+for+a+SHA1+or+MD5+hash",
		mreg => qr{
		<li>(.+?)<\/li>
                  }x
	},
	{
		host => "us.md5.crysm.net",
		path => "/find?md5=%value%",
		meth => "GET",
		mreg => qr{
		<li>(.+?)<\/li>
                  }x        
	},
	{
		host => "nz.md5.crysm.net",
		path => "/find?md5=%value%",
		meth => "GET",
		mreg => qr{
		<li>(.+?)<\/li>
                  }x        
	},
	{
		host => "ice.breaker.free.fr",
		path => "/md5.php?hash=%value%",
		meth => "GET",
		mreg => qr{
		<br>\s-\s(.+?)<br>
                  }x        
	},
    {
        host => "hashchecker.com",
        path => "/index.php",
        meth => "POST",
        content => "search_field=%value%&Submit=search",
        mreg => qr{
		<b>(.+?)<\/b>\sused\scharlist
                  }x        
    } 
];

sub new 
{
	my ($class, $md5) = @_;
	my $this = {};
	bless($this, $class);
	$this->{MD5} = $md5;
	return $this;
}

sub reverse 
{
	my $this = shift;
	return _reverse($this->{MD5});
}

sub _reverse 
{
	my $md5 = shift;	
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
		$page = _post($host,$path,$content);            
        }
        else
        {
		$path =~ s/%value%/$md5/ig;
		$page = _get($host,$path);            
        }         
	next unless $page;
	last SEARCH if(($string) = $page =~ /$site->{mreg}/);
	}
	return $string ? $string : undef;
}

sub reverse_md5
{
	return _reverse(shift);	
}

sub _get
{
	my($url,$path) = @_;
	socket(my $socket, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "Socket Error : $!\n";
	connect($socket,sockaddr_in(80, inet_aton($url))) or die "Connect Error: $!\n";
	send($socket,"GET $path HTTP/1.1\015\012Host: $url\015\012User-Agent: Firefox\015\012Connection: Close\015\012\015\012",0);
	return do { local $/; <$socket> };
}

sub _post
{
	my($url,$path,$content) = @_;
	my $len = length $content;
	socket(my $socket, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "Socket Error : $!\n";
	connect($socket,sockaddr_in(80, inet_aton($url))) or die "Connect Error : $!\n";
	send($socket,"POST $path HTTP/1.1\015\012Host: $url\015\012User-Agent: Firefox\015\012Content-Type: application/x-www-form-urlencoded\015\012Connection: Close\015\012Content-Length: $len\015\012\015\012$content\015\012",0);
	return do { local $/; <$socket> };
}
1;

__END__

=head1 NAME

Digest::MD5::Reverse - MD5 Reverse Lookup

=head1 SYNOPSIS

# Functional style

    use Digest::MD5::Reverse qw(reverse_md5);

    my $plaintext = reverse_md5 $hash;

 # OO style
    use Digest::MD5::Reverse;

    my $md5 = Digest::MD5::Reverse->new($hash);
    my $plaintext = $md5->reverse;

=head1 DESCRIPTION

MD5 sums (see RFC 1321 - The MD5 Message-Digest Algorithm) are used as a one-way
hash of data. Due to the nature of the formula used, it is impossible to reverse
it.

This module provides functions to search several online MD5 hashes database and
return the results (or return undefined if no match found).

We are not breaking security. We are however making it easier to lookup the
source of a MD5 sum.

=head1 EXAMPLES

The simplest way to use this library is to import the reverse_md5() function :

    use Digest::MD5::Reverse qw(reverse_md5);

    print "Data is ".reverse_md5("6df23dc03f9b54cc38a0fc1483df6e21")."\n";

    # Data is foobarbaz
    
    my @md5 = qw(acbd18db4cc2f85cedef654fccc4a4d8 37b51d194a7513e45b56f6524f2d51f2);
    my @plaintext = map (reverse_md5($_), @md5);
    print join " - ", @plaintext;
    
    # foo - bar 

In OO style:

    use Digest::MD5::Reverse;

    my $md5 = Digest::MD5::Reverse->new("6df23dc03f9b54cc38a0fc1483df6e21");
    print "Data is ".$md5->reverse."\n";
    
    # Data is foobarbaz

=head1 LIMITATIONS

It is very slow, because it will search each library until match found or
all library search finished.

=head1 SEE ALSO

L<Digest::MD5>

=head1 AUTHOR

Raoul-Gabriel Urma << blwood@skynet.be >>

=head1 COPYRIGHT & LICENSE

Copyright 2007 Raoul-Gabriel Urma, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut