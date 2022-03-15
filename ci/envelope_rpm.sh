#!/usr/bin/env sh

ls $CI_PROJECT_DIR/build/*.rpm

BIN_TO_PROTECT_IN_RPM="${INSTALL_PREFIX}/sapp"
RPMS_FULL_PATH=`ls $CI_PROJECT_DIR/build/*.rpm | grep -v debug | grep -v devel`
echo "RPMS_TO_BE_ENVELOPE: " $RPMS_FULL_PATH

for RPM in ${RPMS_FULL_PATH[@]}
do
  echo "ENVELOPE: " $RPM
  /root/rebuildrpm_and_envelope.sh $RPM $BIN_TO_PROTECT_IN_RPM $FEATURE_ID $APP_NAME_IN_RPM_SPEC
done