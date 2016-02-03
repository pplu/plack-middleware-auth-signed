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

my $app = sub { return [ 200, [ 'Content-Type' => 'text/plain' ], [ "Hello $_[0]->{REMOTE_USER}" ] ] };
$app = builder {
    enable 'Auth::Signed', get_aki => sub { $user_db->{$_[0]} }, service_region => "us-east-1", service_host => 's3';
    $app;
};

my $ua = LWP::UserAgent->new;

test_psgi ua => $ua, app => $app, client => sub {
    my $cb = shift;

    my $res = $cb->(GET '/');
    is $res->code, 401, 'Got 401 from unsigned request';

    {
      my $req = GET "http://localhost/";

      my @datetime = gmtime();
      my $date = strftime('%Y%m%dT%H%M%SZ',@datetime);

      my $signer = AWS::Signature4->new(-access_key => 'ACCESS_KEY1',
                                        -secret_key => 'SK1');

      $signer->sign($req);

      $res = $cb->($req);

      is $res->code, 200, 'Got 200 from correct user with SK1';
      is $res->content, "Hello user1\@domain1.com";
    }

    {
      my $req = GET "http://localhost/";

      my @datetime = gmtime();
      my $date = strftime('%Y%m%dT%H%M%SZ',@datetime);

      my $signer = AWS::Signature4->new(-access_key => 'ACCESS_KEY1',
                                        -secret_key => 'SK2');

      $signer->sign($req);

      $res = $cb->($req);

      is $res->code, 200, 'Got 200 from correct user with SK2';
      is $res->content, "Hello user1\@domain1.com";
    }

    {
      my $req = GET "http://localhost/";

      my @datetime = gmtime();
      my $date = strftime('%Y%m%dT%H%M%SZ',@datetime);

      my $signer = AWS::Signature4->new(-access_key => 'ACCESS_KEY1',
                                        -secret_key => 'incorrect');

      $signer->sign($req);

      $res = $cb->($req);

      is $res->code, 401, 'Got 401 from incorrect SK';
    }

    {
      my $req = GET "http://localhost/";

      my @datetime = gmtime();
      my $date = strftime('%Y%m%dT%H%M%SZ',@datetime);

      my $signer = AWS::Signature4->new(-access_key => 'INCORRECT_ACCESSKEY',
                                        -secret_key => 'incorrect');

      $signer->sign($req);

      $res = $cb->($req);

      is $res->code, 401, 'Got 401 from inexistant user';
    }



};

done_testing;

