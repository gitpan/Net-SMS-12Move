package Net::SMS::12Move;
#### Package information ####
# Description and copyright:
#   See POD.
####

use strict;
use Carp;
use HTTP::Request::Common qw(POST GET);
use LWP::UserAgent;

our $VERSION = '0.01';

my $MAX_TEXT_LENGTH = 130;

1;

####
# Constructor new()
# Parameters:
#	Hash containing
#		USERS: Reference to array of hash references with keys 'uid', 'pwd'.
#               STATE: Optional. Reference to a tied hash for maintaining persistent state information.
#		       Tie it to Tie::Persistent or Apache::Session::File for example.
#		PROXY: Optional. HTTP proxy such as: http://localhost:8080/
#		VERBOSE: Optional. 0 == nothing, 1 == warnings to STDERR, 2 == all messages to STDERR. Default == 1.
####
sub new {
 my $proto = shift;
 my %params = @_;
 my $class = ref($proto) || $proto;
 my $self  = {};
 bless $self,$class;

 # Check parameters
 my $param_users = $params{'USERS'};
 unless(defined($param_users)) {
  croak("USERS parameter missing!\n");
 }
 unless(@{$param_users}) {
  croak("USERS array is empty!\n");
 }
 foreach (@{$param_users}) {
  unless((ref($_) eq 'HASH') && defined($_->{'uid'}) && length($_->{'uid'}) && defined($_->{'pwd'}) && length($_->{'pwd'})) {
   croak("USERS array is invalid!\n");
  }
 }

 # Set protected fields
 $self->{'-users'} = $param_users;
 $self->{'_state'} = defined($params{'STATE'}) ? $params{'STATE'} : {};
 $self->{'_verbose'} = defined($params{'VERBOSE'}) ? $params{'VERBOSE'} : 1;
 my $ua = new LWP::UserAgent();
 $ua->agent('Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)');
 if (defined($params{'PROXY'})) {
  $ua->proxy(['http'],$params{'PROXY'});
 }
 $self->{'_ua'} = $ua;

 # Return self reference
 return $self;
}


####
# Method:	_get_account
# Description:	Get least recently used user account.
# Parameters:	1. Reference to receive uid.
#		2. Reference to receive pwd.
# Returns:	void
####
sub _get_account {
 my $self = shift;
 my $uidref = shift;
 my $pwdref = shift;
 my $users = $self->{'-users'};
 my $verbose = $self->{'_verbose'};
 my $lastsent = time;
 foreach my $u (@{$users}) {
  my $userstate = $self->_get_user_state($u->{'uid'});
  if ($userstate->{'lastsent'} < $lastsent) {
   $lastsent = $userstate->{'lastsent'};
   $$uidref = $u->{'uid'};
   $$pwdref = $u->{'pwd'};
  }
 }
 return 1;
}


####
# Method:	_get_user_state
# Description:	Gets the users state.
# Parameters:	1. uid
# Returns:	Hash reference.
####
sub _get_user_state {
 my $self = shift;
 my $uid = shift;
 my $result = $self->{'_state'};
 unless(defined($result->{'users'})) {
  $result->{'users'} = {};
 }
 $result = $result->{'users'};
 unless(defined($result->{$uid})) {
  $result->{$uid} = {};
 }
 $result = $result->{$uid};
 unless(defined($result->{'lastsent'})) {
  $result->{'lastsent'} = 0;
 }
 return $result;
}

####
# Method:	_login
# Description:	Logs a user in.
# Parameters:	1. uid
#		2. pwd
# Returns:	dbid or undef on error.
####
sub _login {
 my $self = shift;
 my $uid = shift;
 my $pwd = shift;
 my $cookies = shift;
 my $ua = $self->{'_ua'};
 my $verbose = $self->{'_verbose'};
 my $request = POST('http://www.12move.nl/sms/login.asp',
                    'Content' => ['fase' => 'login',
                                  'username' => $uid,
                                  'password' => $pwd]);
 if ($verbose >= 2) {
  warn "Trying to login.\n";
 }
 my $response = $ua->request($request);
 unless (substr($response->code,0,1) eq '3') {
  if ($verbose >= 1) {
   warn 'Login failed. Expected response code 3xx but got response code: ' . $response->code . "\n";
  }
  return undef;
 }
 # Get location from headers
 my $headers = $response->headers();
 my $location = $headers->header('Location');
 unless($location =~ /^smscenter.asp\?fase=create&username=/o) {
  if ($verbose >= 1) {
   warn "Login failed. Credentials perhaps incorrect.\n";
  }
  return undef;
 }
 # Get dbid
 $request = GET("http://www.12move.nl/sms/smscenter.asp?fase=create&username=$uid");
 if ($verbose >= 2) {
  warn "Getting dbid.\n";
 }
 $response = $ua->request($request);
 unless((substr($response->code(),0,1) eq '2') && ($response->content() =~ /<input type="hidden" name="dbid" value="(\w+)">/o)) {
  if ($verbose >= 1) {
   warn "Login failed (getting dbid). Credentials perhaps incorrect.\n";
  }
  return undef;
 }
 my $dbid = $1;
 if ($verbose >= 2) {
  warn "Login OK (dbid=$dbid).\n";
 }
 return $dbid;
}

####
# Method:	send_text
# Description:	Sends an SMS.
# Parameters:	1. Recipient phone number in int'l format.
#		2. Body text.
# Returns:	Boolean result
####
sub send_text {
 my $self = shift;
 my $phn = shift;
 my $text = shift;
 my $uid;
 my $pwd;
 my $login = 1;
 my $dbid;
 my $verbose = $self->{'_verbose'};
 $self->_get_account(\$uid,\$pwd);
 my $userstate = $self->_get_user_state($uid);
 unless($dbid = $userstate->{'dbid'}) {
  if ($verbose >= 2) {
   warn "User $uid has no dbid. Trying to login (to get one).\n";
  }
  unless($dbid = $self->_login($uid,$pwd)) {
   return 0;
  }
  $userstate->{'dbid'} = $dbid;
  $login = 0;
 }
 if (length($text) > $MAX_TEXT_LENGTH) {
  if ($verbose >= 1) {
   warn "Text length is too long and will be truncated to $MAX_TEXT_LENGTH characters\n";
  }
  $text = substr($text,0,$MAX_TEXT_LENGTH);
 }
 my $ua = $self->{'_ua'};
 my $request = POST('http://www.worldonline.nl/sites/12move/sms/send2.asp',
                    'Content' => ['ToNr' => $phn,
                                  'tekst' => $text,
                                  'dbid' => $dbid]);
 if ($verbose >= 2) {
  warn "Sending 'send SMS' request using uid=$uid.\n";
 }
 my $response = $ua->request($request);
 if (substr($response->code(),0,1) eq '2') {
  if ($verbose >= 2) {
   warn "Send OK.\n";
  }
  $userstate->{'lastsent'} = time;
  return 1;
 }
 if (substr($response->code(),0,1) eq '3') {
  my $headers = $response->headers();
  my $location = $headers->header('Location');
  if ($login && defined($location) && ($location =~ m|^http://www.12move.nl/pages/frameset.asp\?id=1&url=\.\./sms/sorry.asp\?fail\=5$|o)) {
   # Need to login again.
   unless($dbid = $self->_login($uid,$pwd)) {
    return 0;
   }
   $userstate->{'dbid'} = $dbid;
   $request = POST('http://www.worldonline.nl/sites/12move/sms/send2.asp',
                   'Content' => ['ToNr' => $phn,
                                 'tekst' => $text,
                                 'dbid' => $dbid]);
   if ($verbose >= 2) {
    warn "Sending 'send SMS' request again using uid=$uid.\n";
   }
   $response = $ua->request($request);
   if (substr($response->code(),0,1) eq '2') {
    if ($verbose >= 2) {
     warn "Send OK.\n";
    }
    $userstate->{'lastsent'} = time;
    return 1;
   }
  }
 }
 if ($verbose >= 1) {
  warn 'Send failed. Unexpected response code: ' . $response->code() . "\n";
 }
 return 0;
}


__END__


=head1 NAME

Net::SMS::12Move - Send SMS's via free SMS service of www.12move.nl.

=head1 SYNOPSIS

 use Net::SMS::12Move;
 use Tie::Persistent;

 my %state;

 # Read hash from file (created if not exists).
 tie %state, 'Tie::Persistent', '12Move.pdb', 'rw';

 my $users = [
              {'uid' => 'se123456','pwd' => 'secret'},
              {'uid' => 'sh112233','pwd' => 'foofoo'}
             ];

 my $o = new Net::SMS::12Move('USERS' => $users,
                              'STATE' => \%state,
                              'VERBOSE' => 2);
 $o->send_text('+31600001111','test');

 # Save hash back to file.
 untie %state;


=head1 DESCRIPTION

This package contains a class sending SMS's via the free SMS service of
www.12move.nl. It supports multiple user accounts. It can also maintain a
persistent state hash in which the state of the user accounts is saved so
that login's aren't always necessary etc. Unfortunately this web based
service takes a few minutes to send an SMS, but a least it works (for now).

=head1 CLASS METHODS

=over 4

=item new ('USERS' => $users, 'STATE' => $state, 'PROXY' => $proxy, 'VERBOSE' => $level);

Returns a new Net::SMS::12Move object.

B<Parameters:>

B<USERS> Reference to an array of hash references where each hash reference
contains 2 key-value pairs where 'uid' points to the user id and 'pwd'
points to the password.

B<STATE> Optional. If specified, then it must be a hash reference. This
hash reference will be used to maintain state during the lifetime of the
Net::SMS::12Move object. It is advisable to used a tied hash so that the
hash can be saved to and read from a file. See L<Tie::Persistent>.

B<PROXY> Optional. If specified, then it must be a HTTP proxy URL such as
'http://www.myproxy.com:8080/'. Default is no proxy.

B<VERBOSE> Optional. If specified, it must contain an integer between 0 and
2 where 0 is no verbosity at all, 1 means print only warnings to STDERR,
and 2 means print all messages to STDERR. Default value is 1.

=back

=head1 OBJECT METHODS

=over 4

=item send_text($recipient,$message)

Sends a SMS text message. $recipient must contain one recipient
specified in international format (ie +31611112222). $message is the text
message to send.

=back

=head1 HISTORY

=over 4

=item Version 0.01  2002-01-15

Initial version.

=back

=head1 AUTHOR

Craig Manley <cmanley@cpan.org>

=head1 COPYRIGHT

Copyright (C) 2001 Craig Manley.  All rights reserved.
This program is free software; you can redistribute it and/or modify
it under under the same terms as Perl itself. There is NO warranty;
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut