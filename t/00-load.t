#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'BorderPatrol' ) || print "Bail out!
";
}

diag( "Testing BorderPatrol $BorderPatrol::VERSION, Perl $], $^X" );
