#!/bin/bash

CORE_FILE=`find . -name "core*" | head -n 1`

if [ $CORE_FILE ]; then
	gdb ./gtest_sapp_v4 --core=$CORE_FILE  --command=./gdb_analyze_core.cmd
	exit 1
fi
