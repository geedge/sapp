#include "sapp_benchmark.h"
#include <gtest/gtest.h>
extern sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name);

TEST(control, delay) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/control/delay/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(drop, inline_env) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/drop/inline_env/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(forward, inline_simple) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/forward/inline_simple/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(inject, inline_reverse_dir) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/inject/inline_reverse_dir/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(inject, inline_same_dir) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/inject/inline_same_dir/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

int gtest_run(int argc, char *argv[])
{
int ret=RUN_ALL_TESTS();
return ret;
}
