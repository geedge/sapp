FROM git.mesalab.cn:7443/mesa_framework/framework:master

ENV kernelversion 3.10.0-693.el7.x86_64

COPY build/*.rpm /tmp

RUN     cd /tmp \
        && rpm -i *.rpm \
		&& rm -rf /tmp/* \
		&& yum clean all \
		&& rm -rf /var/cache/yum/*