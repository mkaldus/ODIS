#!/bin/bash
./ipac-ng/configure --enable-default-storage=postgre
make
make install
mkdir /etc/ipac-ng
direct=$(pwd)
cp conf/ipac.conf /etc/ipac-ng
cp conf/rules.conf /etc/rules.conf
./ipac-ng/fetchipac -Sv
./ipac-ng/ipacsum -t today
echo "*/1 * * * * root ${direct}/ipac-ng/fetchipac" >> /etc/crontab



yum install -y https://s3-us-west-2.amazonaws.com/grafana-releases/release/grafana-5.0.3-1.x86_64.rpm
service grafana-server start
/sbin/chkconfig --add grafana-server
