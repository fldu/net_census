#!/bin/bash
/usr/bin/masscan $1 -p1-65535 --wait=3 --max-rate $2 -oG - 2>/dev/null | sed 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\\1:\\2/g;/^#.*/d' || exit 0