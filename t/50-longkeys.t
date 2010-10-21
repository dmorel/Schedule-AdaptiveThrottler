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

plan tests => 9;

my $borderpatrol;
ok( $borderpatrol = BorderPatrol->new( memcached_client => $memcached_client ),
    "Created the BorderPatrol object" );

my $test_scheme = { all => {
    first_test    => {
        max     => 1,
        ttl     => 1,
        message => 'blocked',
        value   => 'test_foo'
    }},
    lockout    => 3,
    identifier => 'first_test',
};

$| = 1;

is(($borderpatrol->authorize($test_scheme))[0], BORDERPATROL_AUTHORIZED, "Long key, authorized");
is(($borderpatrol->authorize($test_scheme))[0], BORDERPATROL_BLOCKED, "Long key, blocked");

