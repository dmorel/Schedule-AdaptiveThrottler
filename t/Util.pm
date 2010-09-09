use strict;
use warnings;

sub get_test_memcached_client {
    my ( $msg, $memcached_class, $memcached_client );

    $msg
        = !( $memcached_class
        = eval  { require Cache::Memcached::Fast; 'Cache::Memcached::Fast'; }
        || eval { require 'Cache::Memcached';     "Cache::Memcached"; } )
        && "Could not load a Memcached class";

    $msg ||= !defined $ENV{MEMCACHED_SERVERS}
        && "\$MEMCACHED_SERVERS environment variable needed";

    $msg
        ||= !( $memcached_client
        = $memcached_class->new( { 'servers' => [ split q(,), $ENV{MEMCACHED_SERVERS} ] } ) )
        && "Could not create memcached client";

    return ( $memcached_client, $msg );
}

1;
