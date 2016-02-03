package Plack::Middleware::Auth::Signed;
use 5.008001;
use strict;
use warnings;
use parent qw/Plack::Middleware/;
use Plack::Util::Accessor qw/get_aki signature_ttl service_region service_host/;
use Plack::Request;

use WebService::Amazon::Signature::v4;

our $VERSION = '0.01';

sub prepare_app {
    my $self = shift;

    if ($self->get_aki && ref $self->get_aki ne 'CODE') {
        die 'get_aki should be a code reference';
    }
    die 'service_region should be set' if (not $self->service_region);
    die 'service_host should be set' if (not $self->service_host);
}

sub call {
    my ($self, $env) = @_;

    my $req = Plack::Request->new($env);

    my $headers = $req->headers;

    my $auth = $headers->header('authorization');

    return $self->unauthorized if (not defined $auth);
    #AWS4-HMAC-SHA256 Credential=ACCESS_KEY1/20150428/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=75ca0
    my ($version, $credential, $signed_headers, $signature) = ($auth =~ m/^(.+?) Credential=(.+?), SignedHeaders=(.+?), Signature=(.+?)$/);

    my $got_signature = $signature;
    my ($aki) = ($credential =~ m/^(.+?)\//);
    my $date = $headers->header('x-amz-date');
    my ($split_date, undef) = split /T/, $date;

    return $self->unauthorized if (not defined $got_signature or 
                                   not defined $aki or
                                   not defined $date);
    my $user = $self->get_aki->($aki, $env);

    return $self->unauthorized if (not defined $user or 
                                   ref($user) ne 'HASH' or
                                   not defined $user->{ secret_keys } or
                                   ref($user->{ secret_keys }) ne 'ARRAY');

    foreach my $sk (@{ $user->{ secret_keys } }){
      my $amz = WebService::Amazon::Signature::v4->new(
        scope      => "$split_date/" . $self->service_region . '/' . $self->service_host . '/aws4_request',
        access_key => $aki,
        secret_key => $sk,
      );

      my %req_headers = @{ $req->headers->flatten };
      $req_headers{ lc($_) } = delete $req_headers{ $_ } for (keys %req_headers);
      my %h = map { ($_ => $req_headers{$_}) } split /;/, $signed_headers;
      my $http_req = HTTP::Request->new($req->method, $req->uri, [ %h ], $req->content);

      $amz->from_http_request($http_req);
      my $desired_signature = $amz->calculate_signature;

      if ($desired_signature eq $auth){
        $env->{REMOTE_USER} = $user->{username};
        return $self->app->($env);
      }
    }

    return $self->unauthorized;
}

sub unauthorized {
    my $self = shift;

    my $body      = '401 Authorization required';

    return [
        401,
        [
            'Content-Type'     => 'text/plain',
            'Content-Length'   => length $body,
        ],
        [ $body ],
    ];
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::Signed - Signed request authentication

=head1 SYNOPSIS

  enable "Auth::Signed", secret => "blahblahblah",
      get_aki => sub {
          my ($aki, $env) = @_;
          return { secret_keys => [ ], username => 'myuser@name.com' }; # for $username
      };

=head1 DESCRIPTION

Plack::Middleware::Auth::Signed is a Plack middleware component that
enables authentication via an AWS API compatible signature. 

AWS request signatures are used to authenticate API calls, signing HTTP requests with
a shared secret (Secret Key). The Secret Key is never transmitted over the wire. 

Your C<get_aki> callback is called using two parameters: the Access Key that was 
transmitted in the request headers and the PSGI C<$env> hash. Your callback should return 
a hashref with the accepted secret keys for that access key, and the username for 
setting in the environment.

=head1 CONFIGURATIONS

=over 4

=item get_aki

XXXX

=item password_hashed

XXX

=item secret

XXX

=item signature_ttl

Time-to-live seconds to prevent replay attacks. Defaults to 60.

=back

=head1 AUTHOR

Jose Luis Martinez E<lt>jlmartinez@capside.comE<gt>

=head1 SEE ALSO

L<Plack::Middleware::Auth::Basic>

L<Plack::Middleware::Auth::Digest> on which this plugin was based on 

=cut
