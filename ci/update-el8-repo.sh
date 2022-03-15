#!/bin/sh

rpm -e epel-release

yum install epel-release -y
dnf info epel-release
dnf install 'dnf-command(config-manager)' -y
dnf config-manager --set-enabled PowerTools
dnf update --skip-broken --nobest -y
dnf repolist
dnf --disablerepo="*" --enablerepo="epel" install libunwind -y
dnf  install gperftools  -y