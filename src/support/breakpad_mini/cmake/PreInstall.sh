#!/bin/sh
DST=${RPM_INSTALL_PREFIX}
mkdir -p ${DST}/plug/business/
touch ${DST}/plug/conflist.inf
mkdir -p ${DST}/tsgconf/
touch ${DST}/tsgconf/main.conf

if [[ -z `grep -rn '\[business\]' ${DST}/plug/conflist.inf` ]];then
	echo '[business\]' >> ${DST}/plug/conflist.inf
fi

if [[ -z `grep -rn 'tsg_conn_sketch' ${DST}/plug/conflist.inf` ]];then
	sed -i '/\[business\]/a\./plug/business/tsg_conn_sketch/tsg_conn_sketch.inf' ${DST}/plug/conflist.inf
fi

