#!/usr/bin/env bash
#
# Landlock tutorial at Netdev conferencence 0x16
# https://netdevconf.info/0x16/session.html?How-to-sandbox-a-network-application-with-Landlock

set -ueo pipefail

cd "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"

set -x

sudo pacman -Sy --noconfirm
sudo pacman -S --noconfirm base-devel asp bash-completion vim tmux tree git openbsd-netcat strace cscope lighttpd fcgi php-cgi pacman-contrib

sudo cp -b vmlinuz-landlock-net /boot/vmlinuz-linux
sudo cp -b config/lighttpd.conf /etc/lighttpd/lighttpd.conf
sudo cp -b config/php.ini /etc/php/php.ini
sudo cp -b landlock.h /usr/include/linux/landlock.h
sudo cp web/*.php /srv/http/
cp vimrc ~/.vimrc

sudo systemctl enable --now lighttpd.service
