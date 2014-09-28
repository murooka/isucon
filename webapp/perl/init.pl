#!/usr/bin/env perl

use strict;
use warnings;
use feature 'state';

use DBI;
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

my $logs = db->select_all("SELECT ip, user_id, succeeded, created_at FROM login_log ORDER BY id ASC");
my %user_succeed = ();
for my $log ( @$logs ) {
  if ( $log->{succeeded} ) {
    $user_succeed{$log->{user_id}} = +{
      last_logined_at => $log->{created_at},
      last_logined_ip => $log->{ip},
    }
  }
}

for my $user_id (keys %user_succeed) {
  db->query(
    "UPDATE users SET last_logined_at = ?, last_logined_ip = ? WHERE id = ?",
    $user_succeed{$user_id}->{last_logined_at},
    $user_succeed{$user_id}->{last_logined_ip},
    $user_id,
  );
}
