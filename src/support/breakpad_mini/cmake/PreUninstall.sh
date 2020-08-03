#!/bin/sh
if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/business/
	touch ${DST}/plug/conflist.inf
	mkdir -p ${DST}/tsgconf/
	touch ${DST}/tsgconf/main.conf

	sed -i '/tsg_conn_sketch/d' ${DST}/plug/conflist.inf
fi

