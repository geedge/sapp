#!/bin/sh
echo "splint check $1"
splint -f .splint.rc $1
