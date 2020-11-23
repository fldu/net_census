#!/bin/bash
/usr/sbin/zmap $1 -B $2 -p $3 -C "/app/scan/zmap_config" 2>/dev/null | sed 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\\1:\\2/g;/^#.*/d' || exit 0