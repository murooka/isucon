#!/usr/bin/env perl

use strict;
use warnings;
use feature 'state';

use DBI;
use Redis;
use DBIx::Sunny;
use Data::Dumper;

sub db {
    my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
    my $port = $ENV{ISU4_DB_PORT} || 3306;
    my $username = $ENV{ISU4_DB_USER} || 'root';
    my $password = $ENV{ISU4_DB_PASSWORD};
    my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

    state $dbh = DBIx::Sunny->connect(
        "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
            RaiseError => 1,
            PrintError => 0,
            AutoInactiveDestroy => 1,
            mysql_enable_utf8   => 1,
            mysql_auto_reconnect => 1,
        },
    );
    return $dbh;
}

sub redis {
    state $redis = Redis->new;
    return $redis;
}

my $users = db->select_all("SELECT id, login FROM users");
my %users = map { ($_->{id} => $_->{login} ) } @$users;

my $logs = db->select_all("SELECT ip, user_id, succeeded FROM login_log ORDER BY id ASC");
my %user_fail = ();
my %ip_fail = ();
for my $log ( @$logs ) {
  if ( $log->{succeeded} ) {
    $user_fail{$log->{user_id}} = 0;
    $ip_fail{$log->{ip}} = 0;
  } else {
    $user_fail{$log->{user_id}}++;
    $ip_fail{$log->{ip}}++;
  }
}

for my $user_id ( keys %user_fail ) {
  my $fail = $user_fail{$user_id};
  redis->set("user-$user_id", $fail);
  if ($fail >= $ENV{ISU4_USER_LOCK_THRESHOLD}) {
    redis->sadd('locked_users', $users{$user_id});
  }
}

for my $ip ( keys %ip_fail ) {
  my $fail = $ip_fail{$ip};
  redis->set("ip-$ip", $fail);
  if ($fail >= $ENV{ISU4_IP_BAN_THRESHOLD}) {
    redis->sadd('banned_ips', $ip);
  }
}
