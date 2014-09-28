package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::Dumper;
use Redis;

#use DBIx::QueryLog;
#DBIx::QueryLog->explain(1);

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

sub db {
  my ($self) = @_;
  my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
  my $port = $ENV{ISU4_DB_PORT} || 3306;
  my $username = $ENV{ISU4_DB_USER} || 'root';
  my $password = $ENV{ISU4_DB_PASSWORD};
  my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

  $self->{_db} ||= do {
    DBIx::Sunny->connect(
      "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
      },
    );
  };
}

sub redis {
  my ($self) = @_;

  $self->{_redis} ||= Redis->new;
}

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub user_locked {
  my ($self, $user) = @_;

  return 0 unless $user;

  return $self->redis->sismember('locked_users', $user->{login});
};

sub ip_banned {
  my ($self, $ip) = @_;

  return $self->redis->sismember('banned_ips', $ip);
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);

  if ($self->ip_banned($ip)) {
    return undef, 'banned';
  }

  if ($self->user_locked($user)) {
    return undef, 'locked';
  }

  if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
    $self->redis->set("ip-$ip", 0);
    $self->redis->set("user-$user->{id}", 0);
    $self->redis->srem('banned_ips', $ip);
    $self->redis->srem('locked_users', $user->{login});

    $self->login_log($ip, $user->{id});

    return $user, undef;
  }
  elsif ($user) {
    $self->redis->incr("ip-$ip");
    $self->redis->incr("user-$user->{id}");
    $self->redis->sadd('banned_ips', $ip)
      if $self->redis->get("ip-$ip") > $self->config->{ip_ban_threshold};
    $self->redis->sadd('locked_users', $user->{login})
      if $self->redis->get("user-$user->{id}") > $self->config->{user_lock_threshold};
    return undef, 'wrong_password';
  }
  else {
    $self->redis->incr("ip-$ip");
    $self->redis->sadd('banned_ips', $ip)
      if $self->redis->get("ip-$ip") > $self->config->{ip_ban_threshold};
    return undef, 'wrong_login';
  }
};

sub current_user {
  my ($self, $user_id) = @_;

  $self->db->select_row('SELECT * FROM users WHERE id = ?', $user_id);
};

sub banned_ips {
  my ($self) = @_;

  return $self->redis->smembers('banned_ips') || [];
};

sub locked_users {
  my ($self) = @_;

  return $self->redis->smembers('locked_users') || [];
};

sub login_log {
  my ($self, $ip, $user_id) = @_;
  $self->db->query(
    'UPDATE users SET `last_logined_ip` = ?, `last_logined_at` = NOW() WHERE id = ?',
    $ip, $user_id
  );
};

sub set_flash {
  my ($self, $c, $msg) = @_;
  $c->req->env->{'psgix.session'}->{flash} = $msg;
};

sub pop_flash {
  my ($self, $c, $msg) = @_;
  my $flash = $c->req->env->{'psgix.session'}->{flash};
  delete $c->req->env->{'psgix.session'}->{flash};
  $flash;
};

filter 'session' => sub {
  my ($app) = @_;
  sub {
    my ($self, $c) = @_;
    my $sid = $c->req->env->{'psgix.session.options'}->{id};
    $c->stash->{session_id} = $sid;
    $c->stash->{session}    = $c->req->env->{'psgix.session'};
    $app->($self, $c);
  };
};

get '/' => [qw(session)] => sub {
  my ($self, $c) = @_;

  $c->render('index.tx', { flash => $self->pop_flash($c) });
};

post '/login' => sub {
  my ($self, $c) = @_;
  my $msg;

  my ($user, $err) = $self->attempt_login(
    $c->req->param('login'),
    $c->req->param('password'),
    $c->req->address
  );

  if ($user && $user->{id}) {
    $c->req->env->{'psgix.session'}->{user_id} = $user->{id};
    $c->redirect('/mypage');
  }
  else {
    if ($err eq 'locked') {
      $self->set_flash($c, 'This account is locked.');
    }
    elsif ($err eq 'banned') {
      $self->set_flash($c, "You're banned.");
    }
    else {
      $self->set_flash($c, 'Wrong username or password');
    }
    $c->redirect('/');
  }
};

get '/mypage' => [qw(session)] => sub {
  my ($self, $c) = @_;
  my $user_id = $c->req->env->{'psgix.session'}->{user_id};
  my $user = $self->current_user($user_id);
  my $msg;

  if ($user) {
    $c->render('mypage.tx', { user => $user });
  }
  else {
    $self->set_flash($c, "You must be logged in");
    $c->redirect('/');
  }
};

get '/report' => sub {
  my ($self, $c) = @_;
  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
