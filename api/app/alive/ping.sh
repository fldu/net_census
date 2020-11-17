#!/bin/bash
/usr/sbin/fping -4 -M -r1 -R -a -g $1 2>/dev/null || exit 0