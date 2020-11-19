#!/bin/bash
/usr/sbin/zmap $1 -B $2  2>/dev/null | sed 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\\1:\\2/g;/^#.*/d' || exit 0