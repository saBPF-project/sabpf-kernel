#!/bin/bash

LPATCH_ID=$(grep ^Patch ~/build/kernel/kernel.spec | tail -n1 | awk '{ print $1 }' | sed s/Patch// | sed s/://)
NPATCH_ID=$(($LPATCH_ID + 1 ))
sed -i "/^Patch$LPATCH_ID:\ /a#\ $DESC\nPatch$NPATCH_ID:\ 0001-provbpf.patch" ~/build/kernel/kernel.spec

sed -i "/ApplyOptionalPatch patch-%{stableversion}-redhat.patch/ a ApplyOptionalPatch 0001-provbpf.patch" ~/build/kernel/kernel.spec
