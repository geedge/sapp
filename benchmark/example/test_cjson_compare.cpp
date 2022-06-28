#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "wrap_cJSON.h"
#include "sapp_benchmark.h"
#include "sapp_bchmk_inner.h"

/* 此文件仅为参考样例, 为了简单编译和发布, 没有使用gtest框架, 可根据需求自行添加 */

static int test_cjson_str(const char *json_str1, const char *json_str2, int case_sensitive)
{
	cJSON *json_str1_bin, *json_str2_bin;
	int ret;

	json_str1_bin = cJSON_Parse(json_str1);
	json_str2_bin = cJSON_Parse(json_str2);

	assert(json_str1_bin);
	assert(json_str2_bin);

	ret = cJSON_Compare(json_str1_bin, json_str2_bin, case_sensitive);

	cJSON_free(json_str1_bin);
	cJSON_free(json_str2_bin);

	return ret;
}


static int test_cjson_str_options(const char *json_str1, const char *json_str2, cJSON_Compare_Opt_t opt)
{
	cJSON *json_str1_bin, *json_str2_bin;
	int ret;

	json_str1_bin = cJSON_Parse(json_str1);
	json_str2_bin = cJSON_Parse(json_str2);

	assert(json_str1_bin);
	assert(json_str2_bin);

	ret = cJSON_Compare_options(json_str1_bin, json_str2_bin, opt, NULL);

	cJSON_free(json_str1_bin);
	cJSON_free(json_str2_bin);

	return ret;
}


int main(void)
{
	int ret;

	ret = test_cjson_str("{\"key1\":\"value1\"}", "{ \"key1\" : \"value1\" }  ", 0);
	assert(ret == true);

	ret = test_cjson_str("{\"key1\":\"value1\"}", "{ \"key1\" : \"value1\" }  ", 1);
	assert(ret == true);
	
	ret = test_cjson_str("{\"key1\":\"value1\"}", "{ \"KEY1\" : \"VALUE1\" }  ", 0);
	assert(ret == true);

	ret = test_cjson_str("{\"key1\":\"value1\"}", "{ \"KEY1\" : \"VALUE1\" }  ", 1); /* 区别大小写模式 */
	assert(ret == false);	

	ret = test_cjson_str_options("{\"key1\":\"value1\"}", "{ \"KEY1\" : \"VALUE1\" }  ", CJSON_CMP_OPT_CASE_SENSITIVE); /* 区别大小写模式 */
	assert(ret == false);	

	/* a和b item数量不一致, 但是没有特殊选项, 应该严格比较 */
	ret = test_cjson_str_options("{\"key1\":\"value1\"}", "{\"key1\":\"value1\", \"key2\": \"value2\"}", CJSON_CMP_OPT_NONE);
	assert(ret == false);

	/* a和b item数量都不一致 */
	ret = test_cjson_str_options("{\"key1\":\"value1\", \"key2\": \"value2\"}", "{\"key1\":\"value1\"}", CJSON_CMP_OPT_NONE);
	assert(ret == false);


	ret = test_cjson_str_options("{\"key1\":\"value1\"}", "{\"key1\":\"value1\", \"key2\": \"value2\"}", CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST);
	assert(ret == true);
	printf("ignore a object not exist success!\n");
	
	ret = test_cjson_str_options("{\"key1\":\"value1\", \"key2\": \"value2\"}", "{\"key1\":\"value1\"}", CJSON_CMP_OPT_IGNORE_OBJECTB_NOT_EXIST);
	assert(ret == true);
	printf("ignore b object not exist success!\n");

	/* a和b都是空串, 认为是相同的 */
	ret = test_cjson_str_options("{}", "{}", CJSON_CMP_OPT_NONE);
	assert(ret == true);
	printf("all empty json compare success!\n");
	
	/* 仅一方是空串不认为是相同的 */
	ret = test_cjson_str_options("{}", "{\"keyb\":\"valueb\"}", CJSON_CMP_OPT_NONE);
	assert(ret == false);

	/* a是空串, 认为是相同的 */
	ret = test_cjson_str_options("{}", "{\"keyb\":\"valueb\"}", CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST);
	assert(ret == true);
	
	/* 两个json一个相同的item都没有, 
	   即使同时设置了CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST, CJSON_CMP_OPT_IGNORE_OBJECTB_NOT_EXIST, 
	   其实也不一样, 应该返回false!!
	 */
	ret = test_cjson_str_options("{\"keya\":\"valuea\"}", "{\"keyb1\":\"valueb1\", \"keyb2\": \"valueb2\"}", (cJSON_Compare_Opt_t)((int)CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST|(int)CJSON_CMP_OPT_IGNORE_OBJECTB_NOT_EXIST));
	assert(ret == false);
	printf("all objects is not equal compare success!\n");


	/* 两个数组精确比较 */
	ret = test_cjson_str_options("[{\"keya\":\"valuea\"}]", "[  {\"keya\": \"valuea\"}  ]", CJSON_CMP_OPT_NONE);
	assert(ret == true);
	printf("array compare extractly success!\n");
	
	/* 数组a比b缺少一些数据 */
	ret = test_cjson_str_options("[{\"keya\":\"valuea\"}]", "[  {\"keya\": \"valuea\"}, {\"keyb2\": \"valueb2\"}  ]", CJSON_CMP_OPT_IGNORE_ARRAYA_NOT_EXIST);
	assert(ret == true);
	printf("array a missing some value than b compare success!\n");

	/* 数组b比a缺少一些数据 */
	ret = test_cjson_str_options("[  {\"keya\": \"valuea\"}, {\"key_a2\": \"value_a2\"}  ]", "[{\"keya\":\"valuea\"}]", CJSON_CMP_OPT_IGNORE_ARRAYB_NOT_EXIST);
	assert(ret == true);
	printf("array b missing some value than a compare success!\n");

	/* 两个数组一个相同的数据都没有, 即使设置了IGNORE选项, 也不能算一样的 */
	ret = test_cjson_str_options("[  {\"keya\": \"valuea\"}, {\"key_a2\": \"value_a2\"}  ]", "[{\"keyb\":\"valueb\"},{\"keyb2\":\"valueb2\"}]", (cJSON_Compare_Opt_t)(CJSON_CMP_OPT_IGNORE_ARRAYA_NOT_EXIST|CJSON_CMP_OPT_IGNORE_ARRAYB_NOT_EXIST));
	assert(ret == false);
	printf("all array a and b is not equal compare success!\n");

	/* 数组b有重名的 */
	ret = test_cjson_str_options("[{\"keya\":\"valuea\"}]", "[  {\"keya\": \"valuebbb\"}, {\"keya\": \"valuea\"}  ]", (cJSON_Compare_Opt_t)(CJSON_CMP_OPT_IGNORE_ARRAYA_NOT_EXIST|CJSON_CMP_OPT_DUP_NAME_OBJECT));
	assert(ret == true);
	printf("dup name object in array b compare success!\n");

	/* 数组a和b顺序不一样, 但内容实际是一样的 */
	ret = test_cjson_str_options("[{\"key1\":\"value1\"}, {\"key2\":\"value2\"}]", "[  {\"key2\": \"value2\"}, {\"key1\": \"value1\"}  ]", (cJSON_Compare_Opt_t)(CJSON_CMP_OPT_IGNORE_ARRAYA_NOT_EXIST|CJSON_CMP_OPT_IGNORE_ARRAYB_NOT_EXIST));
	assert(ret == true);
	printf("two array but diff index compare success!\n");

	/* 复杂json结构, a比b缺少一些数据, 但是a里有的b肯定都有, 注意: 必须是同层次的比较! */
	const char *embed_jsona = 
	"{   \
		\"complex_key\": {   \
			\"keya\":\"valuea\",  \
			\"keya2\":\"valuea2\"  \
		}  \
	}";

	const char *embed_jsonb = 
	"{   \
		\"simple_keyb\": 1234, \
		\"simple_keyb2\": \"abcde\", \
		\"complex_key\": {   \
			\"keya\":\"valuea\",  \
			\"keya2\":\"valuea2\",  \
			\"keyxxx\":\"valuexxx\"  \
		}  \
	}";
	ret = test_cjson_str_options(embed_jsona, embed_jsonb, CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST);
	assert(ret == true);
	printf("complex object a missing some keys than b compare success!\n");	


	/* 复杂json结构, a和b有同名的结构complex_key, 而且b还不止一个, 
	   a比b少一些数据, 其中有的一样, 有的不一样, 
	   b里面的最后一个complex_key是a的超集, 有选项CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST时, 可以认为是一样的. 
	*/
	const char *dup_name_jsona = 
	"{   \
		\"complex_key\": {   \
			\"keya\":\"valuea\",  \
			\"keya2\":\"valuea2\"  \
		}  \
	}";	

	const char *dup_name_jsonb = 
	"{   \
		\"complex_key\": {   \
			\"keyx\":\"valuex\",  \
			\"keyxx\":\"valuexx\",  \
			\"keyxxx\":\"valuexxx\"  \
		},  \
		\"complex_key\": {   \
			\"keyy\":\"valuey\",  \
			\"keyyy\":\"valueyy\",  \
			\"keyyyy\":\"valueyyy\"  \
		},  \
		\"complex_key\": {   \
			\"keya\":\"valuea\",  \
			\"keya2\":\"valuea2\",  \
			\"keyb2\":\"valueb3\"  \
		}  \
	}";

	ret = test_cjson_str_options(dup_name_jsona, dup_name_jsonb, (cJSON_Compare_Opt_t)(CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST | CJSON_CMP_OPT_DUP_NAME_OBJECT));
	assert(ret == true);
	printf("dup name object a and b compare success!\n");	
	
	printf("\033[32mAll test success!\033[0m\n");
	
   return 0;
}
