#! /bin/bash

VAR_PWD=`pwd`
TEST_ROOT_DIR="TEST_PROFILE"
AUTO_GEN_FILE_NAME="./auto_gen_gtest_functions.cpp"


#$1 SUITE NAME
#$2 TEST_NAME
#$3 ENTRY JSON NAME
function append_test_case(){
	echo "TEST($1, $2) " >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "{" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "sapp_benchmark_result_t res = sapp_benchmk_wrap_api(\"$TEST_ROOT_DIR/$1/$2/entry.json\");" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "}" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
}


function create_auto_gen_cpp_test_case(){
 	traverse_dir "TEST_PROFILE" ""
}

function create_auto_gen_cpp_header(){
	echo "#include \"sapp_benchmark.h\"" > $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "#include <gtest/gtest.h>" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "extern sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name);" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
}

function create_auto_gen_cpp_tail(){
	echo "int gtest_run(int argc, char *argv[])" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "{" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "int ret=RUN_ALL_TESTS();" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "return ret;" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
	echo "}" >> $VAR_PWD/$AUTO_GEN_FILE_NAME
}


function traverse_dir(){
for file in `ls .`       #注意此处这是两个反引号，表示运行系统命令
do
    if [ -d $file ]  #注意此处之间一定要加上空格，否则会报错
    then
	cd $file
	traverse_dir $file $1
	cd ..
    else
	if [ $file == "entry.json" ]  #在此处处理文件即可
	then
		append_test_case $2 $1 $file
		#echo "### bingo, found entry.json, SUITE_NAME:$2, TEST_NAME:$1"
	fi
    fi
done
}   

`> $VAR_PWD/$AUTO_GEN_FILE_NAME`
#$1 this dir name
#$2 father dir name
cd $TEST_ROOT_DIR
create_auto_gen_cpp_header
create_auto_gen_cpp_test_case
create_auto_gen_cpp_tail
