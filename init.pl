#!/usr/bin/env perl

use strict;
use warnings;
use feature 'state';

use DBI;
use Redis;

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

my $users = db->select_all("SELECT * FROM users");
my $ips = db->select_all("SELECT DISTINCT ip FROM login_log");
for my $user (@$users) {
    my $failures = db->select_row("SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)", $user->{id}, $user->{id});

    redis->set("user-$user->{id}", $failures);
    if ($failures > $ENV{ISU4_USER_LOCK_THRESHOLD}) {
        redis->sadd('locked_users', $user->{login})
    }
}

for my $ip (@$ips) {
    my $failures = db->select_row("SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)", $ip, $ip);

    redis->set("ip-$ip", 0);
    if ($failures > $ENV{ISU4_IP_BAN_THRESHOLD}) {
        redis->srem('banned_ips', $ip);
    }
}
