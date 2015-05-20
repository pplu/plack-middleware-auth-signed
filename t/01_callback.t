use strict;
use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use LWP::UserAgent;
use POSIX qw(strftime);

use AWS::Signature4;

my $user_db = {
  ACCESS_KEY1 => {
    username => 'user1@domain1.com',
    secret_keys => [ 'SK1', 'SK2' ],
  },
  ACCESS_KEY2 => {
    username => 'user2@domain1.com',
    secret_keys => [ 'SK3', 'SK4' ],
  },
};

my $realm    = 'restricted area';

my $app = sub { return [ 200, [ 'Content-Type' => 'text/plain' ], [ "Hello $_[0]->{REMOTE_USER}" ] ] };
$app = builder {
    enable 'Auth::Signed', get_aki => sub { $user_db->{$_[0]} }, service_region => "foo", service_host => 'localhost';
    $app;
};

my $ua = LWP::UserAgent->new;

test_psgi ua => $ua, app => $app, client => sub {
    my $cb = shift;

    my $res = $cb->(GET '/');
    is $res->code, 401;

    my $req = GET "http://localhost/";

    my @datetime = gmtime();
    my $date = strftime('%Y%m%dT%H%M%SZ',@datetime);

    my $signer = AWS::Signature4->new(-access_key => 'ACCESS_KEY1',
                                      -secret_key => 'SK1');

    $signer->sign($req);

    $res = $cb->($req);

    is $res->code, 200;
    is $res->content, "Hello user1\@domain1.com";
};

done_testing;

