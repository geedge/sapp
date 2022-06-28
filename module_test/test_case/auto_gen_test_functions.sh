#! /bin/bash

SRC_DIR=$1
TEST_ROOT_DIR="TEST_PROFILE"
AUTO_GEN_FILE_NAME="./auto_gen_test_functions.cpp"


#$1 SUITE NAME
#$2 TEST_NAME
#$3 ENTRY JSON NAME
function append_test_case(){
	echo "TEST(benchmark_$1, $2) " >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "{" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "sapp_benchmark_result_t res = sapp_benchmk_wrap_api(\"$TEST_ROOT_DIR/$1/$2/entry.json\");" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "}" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
}


function create_auto_gen_cpp_test_case(){
 	traverse_dir "TEST_PROFILE" ""
}

function create_auto_gen_cpp_header(){
	echo "#include \"sapp_benchmark.h\"" > $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "#include <gtest/gtest.h>" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "#include \"MESA_handle_logger.h\"" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	
	echo "extern sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name);" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
}

function create_auto_gen_cpp_tail(){
	echo "int main(int argc, char *argv[])" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "{" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "MESA_handle_runtime_log_creation(\"./etc/sapp_log.conf\");" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "test_sapp_bchmk_lhand = MESA_create_runtime_log_handle(\"./log/test_sapp_benchmark.log\", RLOG_LV_DEBUG);" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "::testing::InitGoogleTest(&argc, argv);" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "int ret=RUN_ALL_TESTS();" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "_exit(ret);" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "return ret;" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
	echo "}" >> $SRC_DIR/$AUTO_GEN_FILE_NAME
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

`> $SRC_DIR/$AUTO_GEN_FILE_NAME`
#$1 source code dir name
#$2 father dir name
cd $SRC_DIR/$TEST_ROOT_DIR

create_auto_gen_cpp_header
create_auto_gen_cpp_test_case

#与gtest_sapp合并, 此处不加main()函数
#create_auto_gen_cpp_tail
