#include "sapp_benchmark.h"
#include <gtest/gtest.h>
#include "MESA_handle_logger.h"
extern sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name);

TEST(benchmark_drop, inline_env) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/drop/inline_env/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(benchmark_forward, inline_simple) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/forward/inline_simple/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(benchmark_inject, inline_reverse_dir) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/inject/inline_reverse_dir/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(benchmark_inject, inline_same_dir) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/inject/inline_same_dir/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(benchmark_inject, tcp_inject_ipv4) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/inject/tcp_inject_ipv4/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(benchmark_inject, tcp_inject_ipv6) 
{
sapp_benchmark_result_t res = sapp_benchmk_wrap_api("TEST_PROFILE/inject/tcp_inject_ipv6/entry.json");
ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

