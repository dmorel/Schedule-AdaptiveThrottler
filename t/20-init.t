#!perl -T

use Test::More tests => 4;
use BorderPatrol qw(set_client authorize);

ok(defined &set_client, "set_client() imported");
ok(defined &authorize, "authorize() imported");
ok(defined BORDERPATROL_BLOCKED, "Block constant defined");
ok(defined BORDERPATROL_AUTHORIZED, "Authorize constant defined");

