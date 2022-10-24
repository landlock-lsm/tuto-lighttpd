#!/usr/bin/env bash

ip a s eth0 | sed -n 's,^\s\+inet\s\+\([0-9.]\+\).*,http://\1,p'
