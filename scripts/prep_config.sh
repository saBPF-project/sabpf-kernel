#!/bin/bash

for i in ~/build/kernel/*-fedora.config
do
	echo $i
  cat ./extra-conf >> $i
	sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" $i
done
