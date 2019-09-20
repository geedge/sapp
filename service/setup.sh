#!/bin/sh

systemctl enable sapp-env

systemctl daemon-reload

#sapp_install_dir=`rpm -qa --queryformat '%{name}-%{version} %{instprefixes}\n' sapp`
sapp_install_dir=`rpm -qa --queryformat '%{instprefixes}\n' sapp`

echo "[Unit]" > /opt/sapp/env/sapp.service.tmp
echo "Description=sapp service" >> /opt/sapp/env/sapp.service.tmp
echo "Wants=network-online.target" >> /opt/sapp/env/sapp.service.tmp
echo "Requires=sapp-env.service" >> /opt/sapp/env/sapp.service.tmp
echo "After=sapp-env.service" >> /opt/sapp/env/sapp.service.tmp
echo "[Service]" >> /opt/sapp/env/sapp.service.tmp
echo "WorkingDirectory=$sapp_install_dir" >> /opt/sapp/env/sapp.service.tmp
echo "ExecStart=$sapp_install_dir/sapp" >> /opt/sapp/env/sapp.service.tmp
echo "Restart=always" >> /opt/sapp/env/sapp.service.tmp
echo "RestartSec=5s" >> /opt/sapp/env/sapp.service.tmp
echo "[Install]" >> /opt/sapp/env/sapp.service.tmp
echo "WantedBy=multi-user.target" >> /opt/sapp/env/sapp.service.tmp

cp -f /opt/sapp/env/sapp.service.tmp /usr/lib/systemd/system/sapp.service

#systemctl enable sapp
systemctl daemon-reload




