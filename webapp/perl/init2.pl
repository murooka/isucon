#!/usr/bin/env perl

use strict;
use warnings;
use feature 'state';

use DBI;
use Redis;
use DBIx::Sunny;

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
print "Num of users:" . scalar(@$users) . "\n";
my $ips = db->select_all("SELECT DISTINCT ip FROM login_log");
print "Num of ips:" . scalar(@$ips) . "\n";

my $tmp;
$tmp = db->select_all("SELECT MAX(id), user_id FROM login_log WHERE succeeded = 1 GROUP BY user_id");
my %last_id_from_user_id = ();
$last_id_from_user_id{$_->{user_id}} = $_->{id} for @$tmp;

my $user_count = 0;
for my $user (@$users) {
    my $last_id = $last_id_from_user_id{$user->{id}} || 0;
    my $failures = db->select_row("SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > ?", $user->{id}, $last_id);

    redis->set("user-$user->{id}", $failures->{failures});
    if ($failures > $ENV{ISU4_USER_LOCK_THRESHOLD}) {
        redis->sadd('locked_users', $user->{login})
    }

    if ($user_count % 1000 == 0) {
	print "Finish: $user_count\n";
    }

    $user_count++;
}

$tmp = db->select_all("SELECT MAX(id), ip FROM login_log WHERE succeeded = 1 GROUP BY ip");
my %last_id_from_ip = ();
$last_id_from_ip = ();
$last_id_from_ip{$_->{ip}} = $_->{id} for @$tmp;

my $ip_count = 0;
for my $ip (@$ips) {
    my $last_id = $last_id_from_ip{$ip} || 0;
    my $failures = db->select_row("SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > ?", $ip, $last_id);

    redis->set("ip-$ip", $failures->{failures});
    if ($failures > $ENV{ISU4_IP_BAN_THRESHOLD}) {
        redis->sadd('banned_ips', $ip);
    }

    if ($ip_count % 1000 == 0) {
	print "Finish: $ip_count\n";
    }
    $ip_count++;
}
