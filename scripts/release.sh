#!/bin/bash

sed -i -e 's/^%define debugbuildsenabled 0/%define debugbuildsenabled 1/g' ~/build/kernel/kernel.spec
