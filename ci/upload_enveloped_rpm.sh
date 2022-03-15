#!/usr/bin/env sh

cd $CI_PROJECT_DIR/build/
cp ~/rpm_upload_tools.py ./

ls -ahl *.rpm

RPM_IS_EL7=`ls -ahl *-pr-*.rpm | grep el7 | wc -l`
RPM_IS_EL8=`ls -ahl *-pr-*.rpm | grep el8 | wc -l`

if [ $RPM_IS_EL7 -eq 1 ]
then
  echo "====== Upload the packed RPM package for CentOS7 ======"
  python3 rpm_upload_tools.py ${PULP3_REPO_NAME_EL7} ${PULP3_DIST_NAME_EL7} *-pr-*el7*.rpm
fi

if [ $RPM_IS_EL8 -eq 1 ]
then
  echo "====== Upload the packed RPM package for CentOS8 ======"
  python3 rpm_upload_tools.py ${PULP3_REPO_NAME_EL8} ${PULP3_DIST_NAME_EL8} *-pr-*el8*.rpm
fi

rm -rf *.rpm