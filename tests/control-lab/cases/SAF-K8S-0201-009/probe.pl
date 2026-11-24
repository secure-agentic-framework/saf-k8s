use strict;
use warnings;
use Errno qw(EAFNOSUPPORT EROFS);
use Fcntl qw(O_APPEND O_WRONLY);
use Socket qw(AF_INET AF_INET6 AF_UNIX SOCK_STREAM);

# A probe invoked by kubelet.service with its normal restrictions. It opens
# sockets without binding or connecting and writes only to case-owned markers.
sub write_marker {
    my ($name) = @_;
    unless (sysopen(my $handle, "/run/saf-unit-proof/$name", O_WRONLY | O_APPEND)) {
        return $! == EROFS ? "read-only" : "errno-" . (0 + $!);
    } else {
        print {$handle} "wrote\n" or die "marker write failed";
        close($handle) or die "marker close failed";
        return "wrote";
    }
}

sub socket_status {
    my ($address_family) = @_;
    return "opened" if socket(my $sock, $address_family, SOCK_STREAM, 0);
    return $! == EAFNOSUPPORT ? "unsupported-family" : "errno-" . (0 + $!);
}

open(my $marker, "<", "/run/saf-unit-proof/protected") or die "marker read failed";
my $content = <$marker>;
close($marker) or die "marker close failed";
my %fields = (
    protected_read => ($content eq "owned marker\n" ? "matched" : "unexpected"),
    protected_write => write_marker("protected"),
    permitted_write => write_marker("permitted"),
    unix_socket => socket_status(AF_UNIX),
    ipv4_socket => socket_status(AF_INET),
    ipv6_socket => socket_status(AF_INET6),
);
print "SAF-UNIT-PROBE ", join(" ", map { "$_=$fields{$_}" } sort keys %fields), "\n";
