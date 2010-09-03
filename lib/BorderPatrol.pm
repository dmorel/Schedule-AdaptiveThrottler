package BorderPatrol;

use warnings;
use strict;

=head1 NAME

BorderPatrol - Limit resource use, according to arbitrary parameters, using a
bucket algorithm with counters stored in memcached.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';
our $DEBUG   = 0;
our $QUIET   = 0;

=head1 SYNOPSIS

=over 4

=item Protect an HTML authentication form

Ban for 5 minutes if more than 5 login attempts for a given username in less
than a minute, OR if more than 50 login attempts from a single IP addressin
less than 5 minutes.

    use BorderPatrol;

    BorderPatrol->set_client(Cache::Memcached::Fast->new(...));

    my ( $status, $msg ) = BorderPatrol->authorize(
        either => {
            ip    => {
                max     => 50,
                ttl     => 300,
                message => 'ip_blocked',
                value   => $client_ip_address,
            },
            login => {
                max     => 5,
                ttl     => 60,
                message => 'login_blocked',
                value   => $username,
            },
        },
        lockout    => 600,
        identifier => 'user_logon',
    );

    return HTTP_FORBIDDEN if $status == BORDERPATROL_BLOCKED;

    ...

=item Robot throttling

Allow at most 10 connection per second for a robot, but do not ban.

    my ( $status, $msg ) = BorderPatrol->authorize(
        all => {
            'ip_ua' => {
                max     => 10,
                ttl     => 1,
                message => 'ip_ua_blocked',
                value   => $client_ip_address .'_'. $user_agent_or_something,
            },
        },
        identifier => 'robot_connect',
    );

    return HTTP_BANDWIDTH_LIMIT_EXCEEDED, '...' if $status == BORDERPATROL_BLOCKED;

=back

=head1 EXPLANATION

This module was originally designed to throttle access to web forms, and help
prevent brute force attacks and DoS conditions. What it does is very simple:
store lists of timestamps, one for each set of parameter defined in the
authorize() call, check the number of timestamps in the previously generated
list isn't over the threshold set in the call, cleanup the list of expired
timestamps from the list, and put the list back in memcached.

It is really a simple bucket algorithm, helped by some of memcached's features
(specifically the automatic cleanup of expired records, particularly useful
when a ban has been specified). 

The interesting thing about it is it can count and throttle anything: if you
need to restrict access to a DB layer to a certain number of calls per minute
per process, for instance, you can do it the exact same way as in the examples
above. Simply use the PID as the 'value' key, and you're set. The possible
applications are endless.

It was written to be fast, efficient, and simpler than other throttling modules
found on CPAN. All what we found was either too complicated, or not fast
enough. Using memcached, a list and a grep on timestamps, where the criteria
(an IP address for instance) are part of the object key, proved satisfactory in
all respects. In particular, we didn't want something using locks, which
introduces a DoS risk all by itself.

=head1 CLASS METHODS

These methods can be used as functions as well, since they are in the
@EXPORT_OK list.

=over4

=item set_client

Set the memcached instance to be used. Takes a Cache::Memcached or
Cache::Memcached::Fast object as first and only parameter. The value is stored
in a class variable, so only one call is needed. It could be any other object
acting as a Cache::Memcached instance (only get() and set() are needed,
really).

=item authorize

Takes a hash or hashref as argument, along these lines:

    authorize(
        <'either'|'all'> => {
            <arbitrary_parameter_name> => {
                max     => <maximum tries>,
                ttl     => <seconds before a record is wiped>,
                message => '<arbitrary message sent back to caller on "blocked">',
                value   => <arbitrarily defined value for grouping>,
            },
            ...
        },
        [ lockout => <ban duration in seconds, if any>, ]
        identifier => '<disambiguation string for memcached key>',
    )

The returned value is a list. The first element is a constant (see
L<EXPORTED CONSTANTS>) and the second element is an arrayref of all the
messages (individually defined in the parameter list for each condition, see
above) for which a block/ban was decided by the counter mechanism.

If the conditions hashref is defined in 'all', all conditions have to be met
for a block or ban to be issued. If it is defined in 'either', any condition
meeting the limits will trigger it.

Since this is meant to be as non-blocking as possible, failure to communicate
with the memcached backend will not issue a ban.  The return value of the
get/set memcached calls could probably benefit from a more clever approach.

=back

=head1 EXPORTED CONSTANTS

=over 4

=item BORDERPATROL_AUTHORIZED

=item BORDERPATROL_BLOCKED

=back

These 2 constants are used to compare with the value of the first member of
the array returned by L<authorize()>.  They are currently 1 and 0, but that may
change and there could be additions in the future. So do not use true/false on
the result of L<authorize()>, since it won't tell you what you think it will.

=head1 NOTES

The discussion came to a point where we thought it would be more efficient to
store timestamp:count:timestamp:count:...  However benchmarks showed no
difference in performance, only in storage size (and even that only under
certain conditions, like many hits in the same second).

=head1 BUGS

Please report any bugs or feature requests to C<bug-borderpatrol at
rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=BorderPatrol>.  I will be
notified, and then you'll automatically be notified of progress on your bug as
I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc BorderPatrol

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=BorderPatrol>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/BorderPatrol>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/BorderPatrol>

=item * Search CPAN

L<http://search.cpan.org/dist/BorderPatrol/>

=back

=head1 ACKNOWLEDGEMENTS

Philippe "BooK" Bruhat
Dennis Kaarsemaker
Kristian Köhntopp
Elizabeth Mattijsen
Ruud Van Tol

This module really is the product of collective thinking.

=head1 AUTHOR

David Morel, C<< <david.morel at amakuru.net> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2010 David Morel & Booking.com.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

use Scalar::Util 'reftype';

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(&authorize &set_client);
our @EXPORT    = qw(
    BORDERPATROL_AUTHORIZED
    BORDERPATROL_BLOCKED
);
our %EXPORT_TAGS = ( ALL => [ @EXPORT_OK, @EXPORT ] );

use constant BORDERPATROL_BLOCKED    => 0;
use constant BORDERPATROL_AUTHORIZED => 1;

my $memcached_client;

sub set_client {

    my $client = pop;
    if (   ref $client !~ 'emcache'
        || !$client->can('set')
        || !$client->can('get') )
    {
        die "Invalid memcached client object";
    }
    return $memcached_client = $client;
}

sub authorize {

    my %params;

    # Call it as a method or a sub, with a hash or a hashref
    if ( @_ < 3 ) {
        %params = %{ pop() };
    }
    else {
        shift if ( @_ % 2 );
        %params = @_;
    }

    my $frozen_time = time;
    my %conditions;

    # Check the conditions

    my $condition_type;
    for my $condition_type_tmp (qw(all either)) {

        if ( exists $params{$condition_type_tmp}
            && reftype $params{$condition_type_tmp} eq 'HASH' )
        {
            %conditions = %{ $params{$condition_type_tmp} };
            die "Conditions improperly defined (must be a hashref)"
                if !%conditions;

            # Check the parameters

            for my $condition_params ( values %conditions ) {
                for my $condition_param_key qw(max ttl message value) {

# message & value are strings (or just anything for 'value'), the rest are integers
                    die
                        "Condition parameter $condition_param_key is '$condition_params->{$condition_param_key}'"
                        if !$condition_params->{$condition_param_key};
                    die
                        "Condition parameter $condition_param_key must be positive integer"
                        if (
                        (      $condition_param_key eq 'max'
                            || $condition_param_key eq 'ttl'
                        )
                        && $condition_params->{$condition_param_key}
                        !~ /^[1-9][0-9]*$/
                        );
                }
            }
            $condition_type = $condition_type_tmp;
            last;    # process either 'all' or 'either', not both
        }
    }
    die "No conditions defined"
        if !$condition_type;

   # if lockout is defined, use the 'lockout/ban' scheme.  if not, we'll use a
   # bucket algorithm
    my $lockout = $params{lockout};
    die "'Lockout' parameter must be positive integer"
        if ( defined $lockout && $lockout !~ /^[1-9][0-9]*$/ );

    my $identifier = $params{identifier};
    die "'Identifier' should be a non-empty string"
        if ( !defined $identifier || length($identifier) < 1 );

   # Loop on the conditions. For 'either', we need to find one that is not yet
   # satisfied, for 'all' we need to find lockouts for all of them

   # Make the memcached keys a identifier + key name + value
   # TODO: Retrieve the records in 1 operation with get_multi
   # @conditions_names = sort keys %conditions;
   # @keys = map { $_ . '#' . $conditions{$_}->{value} } @conditions_names ) {

    my ( $conditions_ok, $conditions_unknown ) = ( 0, 0 );
    my $messages_notok = [];

    while ( my ( $condition_name, $condition ) = each %conditions ) {
        my $memcached_key
            = $identifier . '#' . $condition_name . '#' . $condition->{value};

        my $record = $memcached_client->get($memcached_key);

        if ( defined $record ) {

           # Do we have a 'block' value in the record, in which case we return
           # a message indicating so. The 'block' record will be automatically
           # removed from memcached at the object's expiry time, so don't
           # touch it.
            if ( $record eq 'block' ) {
                push @$messages_notok, $condition->{message};
                print STDERR "Access already blocked by " . __PACKAGE__ . "\n"
                    if $DEBUG;
            }

          # the object in memcached is a list of timestamps, and nothing else.
            elsif ( reftype $record eq 'ARRAY' ) {
                print STDERR "Current timestamps in \$record:  "
                    . join( '|', @$record ). "\n"

                    if $DEBUG;
                print STDERR "Current frozen time: $frozen_time" . "\n"
if $DEBUG;

                # cleanup the records (remove expired timestamps). This is
                # where it all happens, giving us this "magic sliding time
                # window".
                @$record = grep { $_ > $frozen_time } @$record;
                print STDERR "Currently unexpired timestamps in \$record:  "
                    . join( '|', @$record ). "\n"

                    if $DEBUG;

                # Since we are about to add a record, if we already have the
                # max number of records, set to blocked. If no lockout time
                # specified, use the bucket algorithm: deny access, but do not
                # update the record. The expired timestamps will be evicted in
                # due time (next access, possibly), giving us more tokens.
                print STDERR "Maximum is "
                    . $condition->{max}
                    . " and current number of timestamps is "
                    . @$record. "\n"

                    if $DEBUG;
                if ( @$record >= $condition->{max} ) {
                    print STDERR "Maximum reached" . "\n"
if $DEBUG;
                    if ($lockout) {
                        print STDERR "Setting a timed lock" . "\n"
if $DEBUG;
                        $memcached_client->set( $memcached_key, 'block',
                            $lockout );
                    }
                    push @$messages_notok, $condition->{message};
                }

                # Add a timestamp to the list. This is NOT the current
                # timestamp, but a timestamp in the future (a TTL record),
                # which allowws for easy filtering by the grep above. And set
                # the memcached record expiration time at the most recent TTL
                # of the list (for automatic cleanup: the object will be
                # discarded from memcached automatically if it is not updated
                # before the longest TTL)
                else {
                    print STDERR "Adding a timestamp to the list". "\n"
 if $DEBUG;
                    push @$record, $frozen_time + $condition->{ttl};
                    $memcached_client->set( $memcached_key, $record,
                        $condition->{ttl} );
                    $conditions_ok++;
                }
            }
            else {    # This should not happen, but catch it if it does.
                $conditions_unknown++;
            }
        }

        # $record is undef, either not accessible, or not yet created
        else {
            print STDERR "No record found, creating a new one". "\n"
 if $DEBUG;
            my $ret
                = $memcached_client->set( $memcached_key,
                [ $condition->{ttl} + $frozen_time ],
                $condition->{ttl} );
            $conditions_ok++;
        }
    }

    if ( $conditions_unknown && !$QUIET ) {
        warn "Unknown conditions count is over 0, this should not happen";
        print STDERR "Current conditions hash: " . Dumper( \%conditions ). "\n"
;
    }

    # If logic was 'either', 1 'notok' or more should block
    # If logic was 'all', we should have 0 'ok' to block
    # TODO: re-work the variable names because the explanation above is a bit
    # tricky although the logic is correct :(
    if ( $condition_type eq 'either' ) {
        return ( @$messages_notok > 0 )
            ? ( BORDERPATROL_BLOCKED, $messages_notok )
            : ( BORDERPATROL_AUTHORIZED, undef );
    }
    else {    # condition is 'all'
        return ( $conditions_ok == 0 )
            ? ( BORDERPATROL_BLOCKED, $messages_notok )
            : ( BORDERPATROL_AUTHORIZED, undef );
    }
}

1;

__END__


