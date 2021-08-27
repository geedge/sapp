#!/bin/bash
sed -i '1c const unsigned char _sapp_toml_sample_file_image[] = {' $@
echo "const int _sapp_toml_sample_file_image_len = sizeof(_sapp_toml_sample_file_image);" >> $@