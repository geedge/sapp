#include "sapp_benchmark.h"
#include <gtest/gtest.h>


TEST(fake, test_in_two_files)
{
	int res = SAPP_BCHMK_RES_SUCC;
	ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}


int gtest_run2(int argc, char *argv[])
{
	//::testing::InitGoogleTest(&argc, argv);
	int ret=RUN_ALL_TESTS();
	return ret;
}
