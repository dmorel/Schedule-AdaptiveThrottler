use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'BorderPatrol',
    AUTHOR              => q{David Morel <david.morel@amakuru.net>},
    VERSION_FROM        => 'lib/BorderPatrol.pm',
    ABSTRACT_FROM       => 'lib/BorderPatrol.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'BorderPatrol-*' },
);
