package deltarpm;
# Copyright 2012 Thierry Vignaud for Mageia
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself, or under GPL or BSD license.


use strict;
use warnings;
use DynaLoader;

our @ISA = qw(DynaLoader);
our $VERSION = '0.1';

deltarpm->bootstrap($VERSION);


1;

__END__

=head1 NAME

deltarpm - Manipulate delta RPM files

=head1 SYNOPSIS

    use deltarpm;
    use Data::Dumper;

    my $d = deltarpm::read("libreoffice-writer-3.5.5.3-0.3.mga2.x86_64.drpm");
    warn Dumper $d;

=head1 DESCRIPTION

The deltarpm module allows you to manipulate delta RPM files.
It will be used by the C<genhdlist2> utility to generate meta-data aware of delta rpms so that L<urpmi> can perform updates with smaller deltarpms.

=head2 Functions

=over

=item readDeltaRPM($filename)

Return an hash containing information about the deltarpm file.

=back

=head1 COPYRIGHT

Copyright 2012, Mageia

Thierry Vignaud <tv@mageia.org>

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

