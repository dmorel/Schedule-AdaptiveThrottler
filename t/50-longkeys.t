#!perl -T

use strict;
use warnings;
use Data::Dumper;
use BorderPatrol;
#$BorderPatrol::DEBUG = 1;
use t::Util;

use Test::More;

diag "Testing long keys";

my ($memcached_client, $error) = get_test_memcached_client();

plan skip_all => $error if $error;

plan tests => 4;

ok(BorderPatrol->set_client($memcached_client), "Set the memcached client");

# don't remember which comes first in the key (and too lazy to check now), so
# make sure any one of the parts goes over the 250 characters threshold
# (memcached limitation for key length)

my $test_scheme = { all => {
    first_test    => {
        max     => 1,
        ttl     => 1,
        message => 'blocked',
        value   => '01234567890'x25,
    }},
    lockout    => 3,
    identifier => 'superLongKey'x25,
};

my $test_scheme_2 = { all => {
    first_test    => {
        max     => 1,
        ttl     => 1,
        message => 'blocked',
        value   => '01234567890'x25,
    }},
    lockout    => 3,
    identifier => 'superLongKey'x26, # 1 more
};

$| = 1;

is((BorderPatrol->authorize($test_scheme))[0], BORDERPATROL_AUTHORIZED, "Long key, authorized");
is((BorderPatrol->authorize($test_scheme))[0], BORDERPATROL_BLOCKED, "Long key, blocked");

# should be no collision, because of md5sum for long keys
is((BorderPatrol->authorize($test_scheme_2))[0], BORDERPATROL_AUTHORIZED, "Long key, no collision, authorized");
