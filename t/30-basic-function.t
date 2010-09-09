#!perl -T

use strict;
use warnings;
use Data::Dumper;
use BorderPatrol qw(:ALL);
#$BorderPatrol::DEBUG = 1;
use t::Util;

use Test::More;

diag "Testing both flavours of subroutine calls";

my ($memcached_client, $error) = get_test_memcached_client();

plan skip_all => $error if $error;

plan tests => 9;

ok(set_client($memcached_client), "Set the memcached client");

my $test_scheme = { all => {
    first_test    => {
        max     => 5,
        ttl     => 1,
        message => 'blocked',
        value   => 'test_foo'
    }},
    lockout    => 3,
    identifier => 'first_test',
};

diag "parameters passed by hashref";

is((authorize($test_scheme))[0], BORDERPATROL_AUTHORIZED, "Authorized");
for (1..4) { authorize($test_scheme) }
is((authorize($test_scheme))[0], BORDERPATROL_BLOCKED, "Over threshold, blocked");
sleep 2;
is((authorize($test_scheme))[0], BORDERPATROL_BLOCKED, "Locked out for 3 seconds");
sleep 2;
is((authorize($test_scheme))[0], BORDERPATROL_AUTHORIZED, "Ban lifted");

diag "parameters passed by hash";

is((authorize(%$test_scheme))[0], BORDERPATROL_AUTHORIZED, "Authorized");
for (1..3) { authorize($test_scheme) }
is((authorize(%$test_scheme))[0], BORDERPATROL_BLOCKED, "Over threshold, blocked");
sleep 2;
is((authorize(%$test_scheme))[0], BORDERPATROL_BLOCKED, "Locked out for 3 seconds");
sleep 2;
is((authorize(%$test_scheme))[0], BORDERPATROL_AUTHORIZED, "Ban lifted");

#ok(defined BORDERPATROL_BLOCKED, "Block constant defined");
#ok(defined BORDERPATROL_AUTHORIZED, "Authorize constant defined");

