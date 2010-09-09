#!perl -T

use strict;
use warnings;
use Data::Dumper;
use BorderPatrol;
#$BorderPatrol::DEBUG = 1;
use t::Util;

use Test::More;

diag "Testing both flavours of method calls";

my ($memcached_client, $error) = get_test_memcached_client();

plan skip_all => $error if $error;

plan tests => 9;

ok(BorderPatrol->set_client($memcached_client), "Set the memcached client");

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

$| = 1;

diag "Parameters passed by hashref";

is((BorderPatrol->authorize($test_scheme))[0], BORDERPATROL_AUTHORIZED, "Authorized");
for (1..4) { BorderPatrol->authorize($test_scheme) }
is((BorderPatrol->authorize($test_scheme))[0], BORDERPATROL_BLOCKED, "Over threshold, blocked");
sleep 2;
is((BorderPatrol->authorize($test_scheme))[0], BORDERPATROL_BLOCKED, "Locked out for 3 seconds");
sleep 2;
is((BorderPatrol->authorize($test_scheme))[0], BORDERPATROL_AUTHORIZED, "Ban lifted");

diag "Parameters passed by hash";

is((BorderPatrol->authorize(%$test_scheme))[0], BORDERPATROL_AUTHORIZED, "Authorized");
for (1..4) { BorderPatrol->authorize(%$test_scheme) }
is((BorderPatrol->authorize(%$test_scheme))[0], BORDERPATROL_BLOCKED, "Over threshold, blocked");
sleep 2;
is((BorderPatrol->authorize(%$test_scheme))[0], BORDERPATROL_BLOCKED, "Locked out for 3 seconds");
sleep 2;
is((BorderPatrol->authorize(%$test_scheme))[0], BORDERPATROL_AUTHORIZED, "Ban lifted");


#ok(defined BORDERPATROL_BLOCKED, "Block constant defined");
#ok(defined BORDERPATROL_AUTHORIZED, "Authorize constant defined");

