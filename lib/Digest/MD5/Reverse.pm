package Digest::MD5::Reverse;
use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORTER @EXPORT_OK $DATABASE);
use IO::Socket;

$VERSION = '1.0';

@EXPORT_OK = qw(r_md5 r_md5_hex r_md5_base64);
@ISA = ('Exporter');

$DATABASE = [
    {
        url => 'http://us.md5.crysm.net/find?md5=%value%',
        rev => '<li>(.+?)</li>',
        nmv => ''
    },
    {
        url => 'http://nz.md5.crysm.net/find?md5=%value%',
        rev => '<li>(.+?)</li>',
        nmv => ''
    },
    {
        url => 'http://www.schwett.com/md5/?md5value=%value%&md5c=Hash+Match',
        rev => '<h3>(.+?)</h3>',
        nmv => 'No Match Found'
    }
];

sub _encode_hex ($) {
    return unpack 'H*', shift;
}

sub _decode_base64 ($) {
    my $str = shift;

    $str =~ tr|A-Za-z0-9+=/||cd;
    $str =~ s/=+$//;
    $str =~ tr|A-Za-z0-9+/| -_|;

    my $uustr = '';
    my ($i, $l);

    $l = length($str) - 60;
    for ($i = 0; $i <= $l; $i += 60) {
        $uustr .= "M" . substr($str, $i, 60);
    }

    unless ($str eq '') {
        $uustr .= chr(32 + length($str)*3/4) . $str;
    }

    return unpack 'u', $uustr;
}

# Functional interface:

sub r_md5 ($) {
    my $md5_hex = _encode_hex shift;
    return &r_md5_hex($md5_hex);
}

sub r_md5_hex ($) {
    return &_reverse(shift());
}

sub r_md5_base64 ($) {
    my $md5 = _decode_base64 shift;
    return &r_md5($md5);
}

# OOP interface:

sub new {
    my $proto = shift;
    my $class = ref $proto || $proto;
    my $self = {};
    bless $self, $class;
    $self->reset();
    return $self;
}

sub reset {
    my $self = shift;
    delete $self->{_data};
    return $self;
}

sub add {
	my $self = shift;
    return unless @_;
    $self->{_data} .= join '', @_;
    return $self;
}

sub reverse {
	my $self = shift;
    my $md5_hex = _encode_hex $self->{_data};
    return $self->hexreverse($md5_hex);
}

sub hexreverse {
	my $self = shift;
    return &_reverse($self->{_data});
}

sub b64reverse {
	my $self = shift;
    my $md5 = _decode_base64 $self->{_data};
    return $self->reverse($md5);
}

sub clone {
    my $self = shift;

    my $clone = { _data => $self->{_data} };

    bless $clone, ref $self || $self;
}

# Reverse

sub _reverse {
	my $code = shift;

    my $string = '';

    for my $this (@{ $DATABASE }) {
        my $url = $this->{url};
        my $rev = $this->{rev};
        my $nmv = $this->{nmv};

        $url =~ s!%value%!$code!ig;
        my $page = &_getpage($url);
        next unless $page;

        if ($page =~ /$rev/) {
            next if ($nmv && $1 =~ /$nmv/);
            $string = $1;
            last;
        }
    }

    return $string ? $string : undef;
}

sub _getpage {
	my $url = shift;

    my $content = '';

    my $port = 80 if ($url =~ s/^http:\/\///);
    my $host = $1 if ($url =~ s/([^:\/]+)//);
       $port = $1 if ($url =~ s/^:([\d]+)//);

    my $sock = new IO::Socket::INET( PeerHost => $host, PeerPort => $port, Proto => 'tcp', Type => SOCK_STREAM, Timeout => 5 );

    return undef unless $sock;

    $sock->send("GET $url HTTP/1.0\r\n");
    $sock->send("Host: $host\r\n");
    $sock->send("Connection: close\r\n");
    $sock->send("\r\n");
    while ($sock->read(my $tmp, 1024, 0)) {
        $content .= $tmp;
    }
    $sock->shutdown(5);
    $sock->close();

    return $content;
}

1;

__END__

=head1 NAME

Digest::MD5::Reverse - MD5 Reverse Lookup

=head1 SYNOPSIS

 # Functional style
 use Digest::MD5::Reverse qw(r_md5 r_md5_hex r_md5_base64);

 $data = r_md5 $hash;
 $data = r_md5_hex $hash;
 $data = r_md5_base64 $hash;

 # OO style
 use Digest::MD5::Reverse;

 $ctx = Digest::MD5::Reverse->new;

 $ctx->add($hash);
 $data = $ctx->reverse;

=head1 DESCRIPTION

MD5 sums (see RFC 1321 - The MD5 Message-Digest Algorithm) are used as a one-way
hash of data. Due to the nature of the formula used, it is impossible to reverse
it.

This module provides functions to search several online MD5 hashes database and
return the results (or return undefined if no match found).

We are not breaking security. We are however making it easier to lookup the
source of a MD5 sum.

=head1 EXAMPLES

The simplest way to use this library is to import the r_md5_hex()
function (or one of its cousins):

    use Digest::MD5::Reverse qw(r_md5_hex);

    print 'Data is ' r_md5_hex('6df23dc03f9b54cc38a0fc1483df6e21') "\n";

The above example would print out the message

    Data is foobarbaz

In OO style:

    use Digest::MD5::Reverse;

    $reverse = Digest::MD5::Reverse->new;
    $reverse->add('6df23dc03f9b54cc38a0fc1483df6e21');
    $data = $reverse->hexreverse;

    print "Data is $data\n";

You also can make a copy with clone:

	$reverse->clone->hexreverse

=head1 LIMITATIONS

It is very slow, because it will search each library until match found or
all library search finished.

=head1 SEE ALSO

L<Digest::MD5>

=head1 AUTHORS

Digest::MD5::Reverse Written by William Chan (money1109@gmail.com).
http://md5.crysm.net/ Database project by Stephen D Cope.
http://www.schwett.com/md5/ Database project by Canacas.

=head1 COPYRIGHT

Copyright 2005 William Chan.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

See L<http://www.perl.com/perl/misc/Artistic.html>

=cut
