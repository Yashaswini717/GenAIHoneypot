#!/bin/bash
# node-03: the records database. The end of the pivot chain.
#
# A real mariadb runs here rather than a fake listener, because everything an
# attacker does next depends on it behaving like a database: connecting,
# authenticating, listing schemas, dumping tables. A socket that accepts and
# then speaks nonsense is worse than no socket at all.
set -euo pipefail

rm -f /.dockerenv
mkdir -p /run/sshd /var/run/rsyslog /run/mysqld
chown -R mysql:mysql /run/mysqld /var/lib/mysql 2>/dev/null || true

if [[ -f /etc/hosts.extra && -s /etc/hosts.extra ]] && ! grep -q "Departmental hosts" /etc/hosts; then
    cat /etc/hosts.extra >> /etc/hosts
fi

if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    ssh-keygen -A >/dev/null 2>&1
fi

service rsyslog start >/dev/null 2>&1 || rsyslogd
service cron start >/dev/null 2>&1 || cron

# First boot initialises the data directory and loads the seeded records.
if [[ ! -d /var/lib/mysql/mysql ]]; then
    mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1 || true
fi

mysqld_safe --datadir=/var/lib/mysql --skip-syslog >/var/log/mysql-boot.log 2>&1 &

for _ in $(seq 1 30); do
    mysqladmin ping >/dev/null 2>&1 && break
    sleep 1
done

if [[ -f /opt/db/seed.sql ]] && ! mysql -N -B -e "use erp" >/dev/null 2>&1; then
    mysql < /opt/db/seed.sql >/dev/null 2>&1 || true
fi

exec /usr/sbin/sshd -D -e
