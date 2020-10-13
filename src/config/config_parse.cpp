#include "breakpad_mini.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/tomlc99_wrap.h"
#include "field_stat2.h"

/* 静态只读全局变量可以放在代码段, 无需在sapp_global_val里 */
static const char *default_config_file = "./etc/sapp.toml";

static const unsigned char sample_sapp_toml[] = 
{
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x0A,0x23,0x20,0x4E,0x4F,0x54,0x45,0x3A,0x0A,0x23,0x20,0x20,0x20,
	0x20,0x54,0x68,0x65,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x6F,0x66,0x20,0x74,
	0x68,0x69,0x73,0x20,0x66,0x69,0x6C,0x65,0x20,0x69,0x73,0x20,0x74,0x6F,0x6D,0x6C,
	0x20,0x28,0x68,0x74,0x74,0x70,0x73,0x3A,0x2F,0x2F,0x67,0x69,0x74,0x68,0x75,0x62,
	0x2E,0x63,0x6F,0x6D,0x2F,0x63,0x6B,0x74,0x61,0x6E,0x2F,0x74,0x6F,0x6D,0x6C,0x63,
	0x39,0x39,0x29,0x0A,0x23,0x20,0x20,0x20,0x20,0x74,0x6F,0x20,0x6D,0x61,0x6B,0x65,
	0x20,0x76,0x69,0x6D,0x20,0x65,0x64,0x69,0x74,0x6F,0x72,0x20,0x64,0x69,0x73,0x70,
	0x6C,0x61,0x79,0x20,0x63,0x6F,0x6C,0x6F,0x72,0x66,0x75,0x6C,0x20,0x65,0x61,0x73,
	0x69,0x65,0x72,0x20,0x74,0x6F,0x20,0x72,0x65,0x61,0x64,0x2C,0x20,0x0A,0x23,0x20,
	0x20,0x20,0x20,0x79,0x6F,0x75,0x20,0x63,0x61,0x6E,0x20,0x63,0x72,0x65,0x61,0x74,
	0x65,0x20,0x61,0x20,0x73,0x79,0x6D,0x62,0x6F,0x6C,0x69,0x63,0x20,0x6C,0x69,0x6E,
	0x6B,0x73,0x20,0x6E,0x61,0x6D,0x65,0x64,0x20,0x73,0x61,0x70,0x70,0x2E,0x69,0x6E,
	0x69,0x20,0x74,0x6F,0x20,0x73,0x61,0x70,0x70,0x2E,0x74,0x6F,0x6D,0x6C,0x2C,0x20,
	0x6C,0x6E,0x20,0x2D,0x73,0x66,0x20,0x73,0x61,0x70,0x70,0x2E,0x74,0x6F,0x6D,0x6C,
	0x20,0x73,0x61,0x70,0x70,0x2E,0x69,0x6E,0x69,0x0A,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,
	0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x23,0x0A,0x0A,0x5B,
	0x53,0x59,0x53,0x54,0x45,0x4D,0x5D,0x0A,0x69,0x6E,0x73,0x74,0x61,0x6E,0x63,0x65,
	0x5F,0x6E,0x61,0x6D,0x65,0x3D,0x73,0x61,0x70,0x70,0x5F,0x76,0x34,0x2E,0x30,0x0A,
	0x0A,0x5B,0x43,0x50,0x55,0x5D,0x0A,0x77,0x6F,0x72,0x6B,0x65,0x72,0x5F,0x74,0x68,
	0x72,0x65,0x61,0x64,0x73,0x3D,0x34,0x0A,0x23,0x23,0x23,0x20,0x6E,0x6F,0x74,0x65,
	0x2C,0x20,0x62,0x69,0x6E,0x64,0x5F,0x6D,0x61,0x73,0x6B,0x2C,0x20,0x69,0x66,0x20,
	0x79,0x6F,0x75,0x20,0x64,0x6F,0x20,0x6E,0x6F,0x74,0x20,0x77,0x61,0x6E,0x74,0x20,
	0x74,0x6F,0x20,0x62,0x69,0x6E,0x64,0x20,0x74,0x68,0x72,0x65,0x61,0x64,0x20,0x74,
	0x6F,0x20,0x73,0x70,0x65,0x63,0x69,0x61,0x6C,0x20,0x43,0x50,0x55,0x20,0x63,0x6F,
	0x72,0x65,0x2C,0x20,0x6B,0x65,0x65,0x70,0x20,0x69,0x74,0x20,0x65,0x6D,0x70,0x74,
	0x79,0x20,0x61,0x73,0x20,0x5B,0x5D,0x0A,0x62,0x69,0x6E,0x64,0x5F,0x6D,0x61,0x73,
	0x6B,0x3D,0x5B,0x31,0x2C,0x32,0x2C,0x33,0x2C,0x34,0x5D,0x0A,0x0A,0x5B,0x50,0x41,
	0x43,0x4B,0x45,0x54,0x5F,0x49,0x4F,0x5D,0x0A,0x23,0x23,0x23,0x20,0x6E,0x6F,0x74,
	0x65,0x2C,0x20,0x64,0x65,0x70,0x6F,0x6C,0x79,0x6D,0x65,0x6E,0x74,0x2E,0x6D,0x6F,
	0x64,0x65,0x20,0x6F,0x70,0x74,0x69,0x6F,0x6E,0x73,0x3A,0x20,0x5B,0x6D,0x69,0x72,
	0x72,0x6F,0x72,0x2C,0x20,0x69,0x6E,0x6C,0x69,0x6E,0x65,0x2C,0x20,0x74,0x72,0x61,
	0x6E,0x73,0x70,0x61,0x72,0x65,0x6E,0x74,0x2C,0x20,0x64,0x75,0x6D,0x70,0x66,0x69,
	0x6C,0x65,0x5D,0x0A,0x20,0x20,0x5B,0x70,0x61,0x63,0x6B,0x65,0x74,0x5F,0x69,0x6F,
	0x2E,0x64,0x65,0x70,0x6F,0x6C,0x79,0x6D,0x65,0x6E,0x74,0x5D,0x0A,0x20,0x20,0x6D,
	0x6F,0x64,0x65,0x3D,0x6D,0x69,0x72,0x72,0x6F,0x72,0x0A,0x0A,0x23,0x23,0x23,0x20,
	0x6E,0x6F,0x74,0x65,0x2C,0x20,0x69,0x6E,0x74,0x65,0x72,0x66,0x61,0x63,0x65,0x2E,
	0x74,0x79,0x70,0x65,0x20,0x6F,0x70,0x74,0x69,0x6F,0x6E,0x73,0x3A,0x20,0x5B,0x70,
	0x61,0x67,0x2C,0x70,0x63,0x61,0x70,0x2C,0x6D,0x61,0x72,0x73,0x69,0x6F,0x5D,0x0A,
	0x20,0x20,0x5B,0x70,0x61,0x63,0x6B,0x65,0x74,0x5F,0x69,0x6F,0x2E,0x69,0x6E,0x74,
	0x65,0x72,0x6E,0x61,0x6C,0x2E,0x69,0x6E,0x74,0x65,0x72,0x66,0x61,0x63,0x65,0x5D,
	0x0A,0x20,0x20,0x74,0x79,0x70,0x65,0x3D,0x70,0x63,0x61,0x70,0x0A,0x20,0x20,0x6E,
	0x61,0x6D,0x65,0x3D,0x65,0x74,0x68,0x30,0x0A,0x0A,0x20,0x20,0x5B,0x70,0x61,0x63,
	0x6B,0x65,0x74,0x5F,0x69,0x6F,0x2E,0x65,0x78,0x74,0x65,0x72,0x6E,0x61,0x6C,0x2E,
	0x69,0x6E,0x74,0x65,0x72,0x66,0x61,0x63,0x65,0x5D,0x0A,0x20,0x20,0x74,0x79,0x70,
	0x65,0x3D,0x70,0x63,0x61,0x70,0x0A,0x20,0x20,0x6E,0x61,0x6D,0x65,0x3D,0x65,0x74,
	0x68,0x30,0x0A,0x0A,0x5B,0x53,0x54,0x52,0x45,0x41,0x4D,0x5D,0x0A,0x20,0x20,0x5B,
	0x73,0x74,0x72,0x65,0x61,0x6D,0x2E,0x74,0x63,0x70,0x5D,0x0A,0x20,0x20,0x6D,0x61,
	0x78,0x3D,0x31,0x30,0x30,0x30,0x30,0x30,0x0A,0x20,0x20,0x74,0x69,0x6D,0x65,0x6F,
	0x75,0x74,0x3D,0x33,0x30,0x0A,0x20,0x20,0x73,0x79,0x6E,0x5F,0x6D,0x61,0x6E,0x64,
	0x61,0x74,0x6F,0x72,0x79,0x3D,0x31,0x0A,0x20,0x20,0x72,0x65,0x6F,0x72,0x64,0x65,
	0x72,0x5F,0x70,0x6B,0x74,0x5F,0x6D,0x61,0x78,0x3D,0x35,0x0A,0x20,0x20,0x20,0x20,
	0x5B,0x73,0x74,0x72,0x65,0x61,0x6D,0x2E,0x74,0x63,0x70,0x2E,0x69,0x6E,0x6A,0x65,
	0x63,0x74,0x5D,0x0A,0x09,0x20,0x20,0x6C,0x69,0x6E,0x6B,0x5F,0x6D,0x73,0x73,0x3D,
	0x31,0x34,0x36,0x30,0x0A,0x09,0x20,0x20,0x0A,0x09,0x20,0x20,0x5B,0x73,0x74,0x72,
	0x65,0x61,0x6D,0x2E,0x74,0x63,0x70,0x2E,0x69,0x6E,0x6A,0x65,0x63,0x74,0x2E,0x72,
	0x73,0x74,0x5D,0x0A,0x09,0x20,0x20,0x6E,0x75,0x6D,0x62,0x65,0x72,0x3D,0x33,0x0A,
	0x09,0x20,0x20,0x73,0x69,0x67,0x6E,0x61,0x74,0x75,0x72,0x65,0x5F,0x65,0x6E,0x61,
	0x62,0x6C,0x65,0x64,0x3D,0x31,0x0A,0x20,0x20,0x20,0x20,0x20,0x20,0x73,0x69,0x67,
	0x6E,0x61,0x74,0x75,0x72,0x65,0x5F,0x73,0x65,0x65,0x64,0x31,0x3D,0x36,0x35,0x35,
	0x33,0x35,0x0A,0x20,0x20,0x20,0x20,0x20,0x20,0x73,0x69,0x67,0x6E,0x61,0x74,0x75,
	0x72,0x65,0x5F,0x73,0x65,0x65,0x64,0x32,0x3D,0x31,0x33,0x0A,0x09,0x0A,0x20,0x20,
	0x5B,0x73,0x74,0x72,0x65,0x61,0x6D,0x2E,0x75,0x64,0x70,0x5D,0x0A,0x20,0x20,0x6D,
	0x61,0x78,0x3D,0x31,0x30,0x30,0x30,0x30,0x30,0x0A,0x20,0x20,0x74,0x69,0x6D,0x65,
	0x6F,0x75,0x74,0x3D,0x33,0x30,0x0A,0x0A,0x0A,0x5B,0x50,0x52,0x4F,0x46,0x49,0x4C,
	0x49,0x4E,0x47,0x5D,0x0A,0x20,0x20,0x5B,0x70,0x72,0x6F,0x66,0x69,0x6C,0x69,0x6E,
	0x67,0x2E,0x70,0x6B,0x74,0x5F,0x6C,0x61,0x74,0x65,0x6E,0x63,0x79,0x5D,0x0A,0x20,
	0x20,0x20,0x20,0x65,0x6E,0x61,0x62,0x6C,0x65,0x64,0x3D,0x30,0x0A,0x09,0x23,0x23,
	0x23,0x20,0x6E,0x6F,0x74,0x65,0x2C,0x20,0x74,0x68,0x72,0x65,0x73,0x68,0x6F,0x6C,
	0x64,0x20,0x75,0x6E,0x69,0x74,0x20,0x69,0x73,0x20,0x6D,0x69,0x63,0x72,0x6F,0x73,
	0x65,0x63,0x6F,0x6E,0x64,0x73,0x20,0x28,0x75,0x73,0x29,0x0A,0x20,0x20,0x20,0x20,
	0x74,0x68,0x72,0x65,0x73,0x68,0x6F,0x6C,0x64,0x3D,0x31,0x30,0x30,0x30,0x30,0x0A,
	0x09,0x0A,0x20,0x20,0x5B,0x70,0x72,0x6F,0x66,0x69,0x6C,0x69,0x6E,0x67,0x2E,0x73,
	0x61,0x6E,0x69,0x74,0x79,0x5F,0x63,0x68,0x65,0x63,0x6B,0x5D,0x0A,0x20,0x20,0x72,
	0x61,0x77,0x5F,0x70,0x6B,0x74,0x5F,0x62,0x72,0x6F,0x6B,0x65,0x6E,0x5F,0x65,0x6E,
	0x61,0x62,0x6C,0x65,0x64,0x3D,0x30,0x0A,0x20,0x20,0x73,0x79,0x6D,0x62,0x6F,0x6C,
	0x5F,0x63,0x6F,0x6E,0x66,0x6C,0x69,0x63,0x74,0x5F,0x65,0x6E,0x61,0x62,0x6C,0x65,
	0x64,0x3D,0x30,0x0A,0x20,0x20,0x0A,0x20,0x20,0x5B,0x70,0x72,0x6F,0x66,0x69,0x6C,
	0x69,0x6E,0x67,0x2E,0x6C,0x6F,0x67,0x5D,0x0A,0x20,0x20,0x20,0x20,0x6C,0x65,0x76,
	0x65,0x6C,0x3D,0x32,0x30,0x0A,0x20,0x20,0x20,0x20,0x0A,0x09,0x5B,0x70,0x72,0x6F,
	0x66,0x69,0x6C,0x69,0x6E,0x67,0x2E,0x6C,0x6F,0x67,0x2E,0x66,0x69,0x65,0x6C,0x64,
	0x5F,0x73,0x74,0x61,0x74,0x5D,0x0A,0x09,0x20,0x69,0x6E,0x74,0x65,0x72,0x76,0x61,
	0x6C,0x3D,0x33,0x0A,0x20,0x20,0x20,0x20,0x20,0x73,0x65,0x72,0x76,0x65,0x72,0x5F,
	0x69,0x70,0x3D,0x31,0x39,0x32,0x2E,0x31,0x36,0x38,0x2E,0x31,0x2E,0x31,0x0A,0x20,
	0x20,0x20,0x20,0x20,0x73,0x65,0x72,0x76,0x65,0x72,0x5F,0x70,0x6F,0x72,0x74,0x3D,
	0x31,0x32,0x33,0x34,0x35,0x0A,0x0A,0x5B,0x54,0x4F,0x4F,0x4C,0x53,0x5D,0x0A,0x20,
	0x20,0x5B,0x74,0x6F,0x6F,0x6C,0x73,0x2E,0x70,0x6B,0x74,0x5F,0x64,0x75,0x6D,0x70,
	0x5D,0x0A,0x20,0x20,0x20,0x65,0x6E,0x61,0x62,0x6C,0x65,0x64,0x3D,0x31,0x0A,0x20,
	0x20,0x20,0x23,0x23,0x23,0x20,0x6E,0x6F,0x74,0x65,0x2C,0x20,0x6D,0x6F,0x64,0x65,
	0x20,0x6F,0x70,0x74,0x69,0x6F,0x6E,0x73,0x20,0x76,0x61,0x6C,0x75,0x65,0x3A,0x5B,
	0x73,0x74,0x6F,0x72,0x61,0x67,0x65,0x2C,0x20,0x75,0x64,0x70,0x5F,0x73,0x6F,0x63,
	0x6B,0x65,0x74,0x5D,0x0A,0x20,0x20,0x20,0x6D,0x6F,0x64,0x65,0x3D,0x75,0x64,0x70,
	0x5F,0x73,0x6F,0x63,0x6B,0x65,0x74,0x0A,0x20,0x20,0x20,0x42,0x53,0x44,0x5F,0x70,
	0x61,0x63,0x6B,0x65,0x74,0x5F,0x66,0x69,0x6C,0x74,0x65,0x72,0x3D,0x69,0x70,0x0A,
	0x20,0x20,0x20,0x0A,0x20,0x20,0x20,0x5B,0x74,0x6F,0x6F,0x6C,0x73,0x2E,0x70,0x6B,
	0x74,0x5F,0x64,0x75,0x6D,0x70,0x2E,0x74,0x68,0x72,0x65,0x61,0x64,0x73,0x5D,0x0A,
	0x20,0x20,0x20,0x23,0x23,0x23,0x20,0x6E,0x6F,0x74,0x65,0x2C,0x20,0x69,0x66,0x20,
	0x79,0x6F,0x75,0x20,0x77,0x61,0x6E,0x74,0x20,0x65,0x6E,0x61,0x62,0x6C,0x65,0x20,
	0x70,0x6B,0x74,0x20,0x64,0x75,0x6D,0x70,0x20,0x69,0x6E,0x20,0x61,0x6C,0x6C,0x20,
	0x74,0x68,0x72,0x65,0x61,0x64,0x2C,0x20,0x73,0x65,0x74,0x20,0x64,0x75,0x6D,0x70,
	0x5F,0x74,0x68,0x72,0x65,0x61,0x64,0x5F,0x61,0x6C,0x6C,0x5F,0x65,0x6E,0x61,0x62,
	0x6C,0x65,0x64,0x3D,0x31,0x2C,0x0A,0x20,0x20,0x20,0x23,0x23,0x23,0x20,0x20,0x20,
	0x20,0x20,0x20,0x20,0x69,0x66,0x20,0x64,0x75,0x6D,0x70,0x5F,0x74,0x68,0x72,0x65,
	0x61,0x64,0x5F,0x61,0x6C,0x6C,0x5F,0x65,0x6E,0x61,0x62,0x6C,0x65,0x64,0x3D,0x30,
	0x2C,0x20,0x74,0x68,0x65,0x6E,0x20,0x75,0x73,0x65,0x20,0x64,0x75,0x6D,0x70,0x5F,
	0x74,0x68,0x72,0x65,0x61,0x64,0x5F,0x69,0x64,0x20,0x74,0x6F,0x20,0x73,0x70,0x65,
	0x63,0x69,0x66,0x79,0x20,0x73,0x65,0x70,0x61,0x72,0x61,0x74,0x65,0x20,0x74,0x68,
	0x72,0x65,0x61,0x64,0x2E,0x0A,0x20,0x20,0x20,0x61,0x6C,0x6C,0x5F,0x74,0x68,0x72,
	0x65,0x61,0x64,0x73,0x5F,0x65,0x6E,0x61,0x62,0x6C,0x65,0x64,0x3D,0x31,0x0A,0x20,
	0x20,0x20,0x0A,0x20,0x20,0x20,0x23,0x23,0x23,0x20,0x6E,0x6F,0x74,0x65,0x2C,0x20,
	0x64,0x75,0x6D,0x70,0x5F,0x74,0x68,0x72,0x65,0x61,0x64,0x5F,0x69,0x64,0x20,0x73,
	0x74,0x61,0x72,0x74,0x20,0x66,0x72,0x6F,0x6D,0x20,0x30,0x2C,0x20,0x6D,0x61,0x78,
	0x20,0x69,0x73,0x20,0x43,0x50,0x55,0x2E,0x77,0x6F,0x72,0x6B,0x65,0x72,0x5F,0x74,
	0x68,0x72,0x65,0x61,0x64,0x73,0x2D,0x31,0x0A,0x20,0x20,0x20,0x64,0x75,0x6D,0x70,
	0x5F,0x74,0x68,0x72,0x65,0x61,0x64,0x5F,0x69,0x64,0x3D,0x5B,0x30,0x2C,0x31,0x2C,
	0x32,0x2C,0x33,0x2C,0x34,0x5D,0x0A,0x20,0x20,0x20,0x0A,0x20,0x20,0x20,0x5B,0x74,
	0x6F,0x6F,0x6C,0x73,0x2E,0x70,0x6B,0x74,0x5F,0x64,0x75,0x6D,0x70,0x2E,0x75,0x64,
	0x70,0x5D,0x0A,0x20,0x20,0x20,0x20,0x20,0x63,0x6F,0x6D,0x6D,0x61,0x6E,0x64,0x5F,
	0x70,0x6F,0x72,0x74,0x3D,0x31,0x32,0x33,0x34,0x35,0x0A,0x0A,0x20,0x20,0x20,0x5B,
	0x74,0x6F,0x6F,0x6C,0x73,0x2E,0x70,0x6B,0x74,0x5F,0x64,0x75,0x6D,0x70,0x2E,0x73,
	0x74,0x6F,0x72,0x61,0x67,0x65,0x5D,0x0A,0x20,0x20,0x20,0x20,0x20,0x23,0x23,0x23,
	0x20,0x6E,0x6F,0x74,0x65,0x2C,0x20,0x70,0x61,0x74,0x68,0x20,0x6D,0x75,0x73,0x74,
	0x20,0x62,0x65,0x20,0x64,0x6F,0x75,0x62,0x6C,0x65,0x20,0x71,0x75,0x6F,0x74,0x61,
	0x74,0x69,0x6F,0x6E,0x20,0x6D,0x61,0x72,0x6B,0x20,0x65,0x78,0x74,0x65,0x6E,0x73,
	0x69,0x6F,0x6E,0x2C,0x20,0x66,0x6F,0x72,0x20,0x65,0x78,0x61,0x6D,0x70,0x6C,0x65,
	0x2C,0x20,0x20,0x70,0x61,0x74,0x68,0x3D,0x22,0x2F,0x64,0x65,0x76,0x2F,0x73,0x68,
	0x6D,0x2F,0x70,0x6B,0x74,0x5F,0x64,0x75,0x6D,0x70,0x22,0x0A,0x20,0x20,0x20,0x20,
	0x20,0x70,0x61,0x74,0x68,0x3D,0x22,0x2F,0x64,0x65,0x76,0x2F,0x73,0x68,0x6D,0x2F,
	0x70,0x6B,0x74,0x5F,0x64,0x75,0x6D,0x70,0x22,0x0A,0x09,0x20,0x23,0x23,0x23,0x23,
	0x20,0x6E,0x6F,0x74,0x65,0x2C,0x20,0x66,0x69,0x6C,0x65,0x20,0x73,0x69,0x7A,0x65,
	0x20,0x75,0x6E,0x69,0x74,0x3A,0x20,0x4D,0x42,0x0A,0x20,0x20,0x20,0x20,0x20,0x66,
	0x69,0x6C,0x65,0x5F,0x73,0x69,0x7A,0x65,0x5F,0x6D,0x61,0x78,0x5F,0x70,0x65,0x72,
	0x5F,0x74,0x68,0x72,0x65,0x61,0x64,0x3D,0x31,0x30,0x30,0x30,0x30,0x20,0x0A,0x0A,
	0x23,0x23,0x23,0x20,0x6E,0x6F,0x74,0x65,0x3A,0x0A,0x23,0x23,0x23,0x20,0x54,0x68,
	0x65,0x73,0x65,0x20,0x63,0x6F,0x6E,0x66,0x69,0x67,0x75,0x72,0x61,0x74,0x69,0x6F,
	0x6E,0x73,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x69,0x73,0x20,0x63,0x6F,0x6D,
	0x70,0x6C,0x65,0x78,0x20,0x61,0x6E,0x64,0x20,0x64,0x69,0x66,0x66,0x69,0x63,0x75,
	0x6C,0x74,0x20,0x74,0x6F,0x20,0x64,0x65,0x73,0x63,0x72,0x69,0x62,0x65,0x20,0x77,
	0x69,0x74,0x68,0x20,0x74,0x6F,0x6D,0x6C,0x20,0x67,0x72,0x61,0x6D,0x6D,0x61,0x72,
	0x2C,0x0A,0x23,0x23,0x23,0x20,0x73,0x6F,0x2C,0x20,0x63,0x72,0x65,0x61,0x74,0x65,
	0x20,0x61,0x20,0x49,0x6E,0x64,0x65,0x70,0x65,0x6E,0x64,0x65,0x6E,0x74,0x20,0x63,
	0x6F,0x6E,0x66,0x69,0x67,0x20,0x66,0x69,0x6C,0x65,0x20,0x74,0x6F,0x20,0x64,0x65,
	0x73,0x63,0x72,0x69,0x70,0x74,0x69,0x6F,0x6E,0x20,0x73,0x70,0x65,0x63,0x69,0x66,
	0x69,0x63,0x20,0x69,0x6E,0x66,0x6F,0x72,0x6D,0x61,0x74,0x69,0x6F,0x6E,0x2E,0x0A,
	0x5B,0x53,0x50,0x45,0x43,0x49,0x41,0x4C,0x5F,0x43,0x4F,0x4E,0x46,0x49,0x47,0x5F,
	0x4C,0x49,0x4E,0x4B,0x5D,0x09,0x20,0x0A,0x20,0x70,0x72,0x6F,0x6A,0x65,0x63,0x74,
	0x5F,0x63,0x6F,0x6E,0x66,0x3D,0x22,0x2E,0x2F,0x65,0x74,0x63,0x2F,0x70,0x72,0x6F,
	0x6A,0x65,0x63,0x74,0x5F,0x6C,0x69,0x73,0x74,0x2E,0x63,0x6F,0x6E,0x66,0x22,0x0A,
	0x20,0x70,0x6C,0x75,0x67,0x69,0x6E,0x5F,0x63,0x6F,0x6E,0x66,0x3D,0x22,0x2E,0x2F,
	0x65,0x74,0x63,0x2F,0x70,0x6C,0x75,0x67,0x69,0x6E,0x2E,0x63,0x6F,0x6E,0x66,0x22,
	0x0A,0x20,0x70,0x6C,0x75,0x67,0x69,0x6E,0x5F,0x65,0x6E,0x74,0x72,0x79,0x6C,0x69,
	0x73,0x74,0x5F,0x63,0x6F,0x6E,0x66,0x3D,0x22,0x2E,0x2F,0x65,0x74,0x63,0x2F,0x65,
	0x6E,0x74,0x72,0x79,0x6C,0x69,0x73,0x74,0x2E,0x63,0x6F,0x6E,0x66,0x22,0x0A,0x20,
	0x73,0x65,0x6E,0x64,0x5F,0x72,0x61,0x77,0x5F,0x63,0x6F,0x6E,0x66,0x3D,0x22,0x2E,
	0x2F,0x65,0x74,0x63,0x2F,0x73,0x65,0x6E,0x64,0x5F,0x72,0x61,0x77,0x5F,0x70,0x6B,
	0x74,0x2E,0x63,0x6F,0x6E,0x66,0x22,0x0A,0x20,0x76,0x78,0x6C,0x61,0x6E,0x5F,0x73,
	0x70,0x6F,0x72,0x74,0x5F,0x73,0x65,0x72,0x76,0x69,0x63,0x65,0x5F,0x6D,0x61,0x70,
	0x5F,0x63,0x6F,0x6E,0x66,0x3D,0x22,0x2E,0x2F,0x65,0x74,0x63,0x2F,0x76,0x78,0x6C,
	0x61,0x6E,0x5F,0x73,0x70,0x6F,0x72,0x74,0x5F,0x73,0x65,0x72,0x76,0x69,0x63,0x65,
	0x5F,0x6D,0x61,0x70,0x2E,0x63,0x6F,0x6E,0x66,0x2E,0x63,0x6F,0x6E,0x66,0x22,0x0A,
	0x20,0x0A,0x20,
};


static void special_usage(void)
{
	printf("\033[1;31;40m[Error]open %s error!\033[0m\n", default_config_file);
	printf("\033[1;31;40m[Error]This is sapp version4.0, use sapp.toml instead of main.conf!\033[0m\n");
	printf("\033[1;31;40m[Error]You should run ./sapp --sample-config to generate sapp.toml!\033[0m\n");
/*
	sapp_log(30, ~0, ~0, "[Error]open %s error!", default_config_file);
	sapp_log(30, ~0, ~0, "[Error]This is sapp version4.0, use sapp.toml instead of main.conf!");
	sapp_log(30, ~0, ~0, "[Error]You should run ./sapp --sample-config to generate sapp.toml!");
*/
}

static inline int is_file_exist(const char *filename)
{
	struct stat fstat;
	int fres, ret;

	fres = stat(filename, &fstat);
	if(fres < 0){
		if(ENOENT == errno){
			ret = 0;
		}
	}else{
		ret = 1;
	}

	return ret;
}

/* 对于相同类型的配置, 命令行参数优先, 覆盖sapp.toml中的配置 */
void sapp_cla_override_cfg_file(void)
{
	char *cmd_args;
	sapp_config_t *pconfig = &sapp_global_val->config;

	if (sapp_get_cla_raw("coredump", &cmd_args) >= 0){ 
		breakpad_segv_generate();
	}
	
	if (sapp_get_cla_raw("dumpfile", &cmd_args) >= 0)
	{ /* dumpfile模式自动覆盖interface配置 */
		strcpy(pconfig->packet_io.depolyment_mode_str, "dumpfile");
		pconfig->packet_io.depolyment_mode_bin = DEPOLYMENT_MODE_MIRROR;
		sapp_global_val->individual_fixed.depolyment_mode_private = NET_CONN_PARALLEL;
		strcpy(pconfig->packet_io.internal.interface.type_str, "pcap");
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_PCAP_DUMPFILE;
	}

	if (sapp_get_cla_raw("dumpfile-file", &cmd_args) >= 0)
	{
		strncpy(sapp_global_val->config.packet_io.pcap_dumpfile_name, cmd_args, NAME_MAX);
	}

		return;
	}

void sapp_generate_sample_config(void)
{
	FILE *fp;

	system("mkdir -p ./etc");

	fp = fopen(default_config_file, "w+");
	if(NULL == fp){
		printf("\033[1;31;40m[Error]open %s error, %s!\033[0m\n", default_config_file, strerror(errno));
		return;
	}

	fwrite(sample_sapp_toml, sizeof(sample_sapp_toml), 1, fp);

	fclose(fp);

	printf("\033[32mThe sample config file saved to ./etc/sapp.toml,\033[0m\n");
	printf("\033[32mYou should change some parameters to suit the current system environment!\033[0m\n");
}

static int pkt_dump_thread_id_convert(void)
{
	sapp_config_tools_pktdump_t *pdump;
	int i, index;
	
	pdump = &sapp_global_val->config.tools.pkt_dump;

	if(pdump->dump_all_thread_enabled != 0){
		memset(pdump->dump_thread_id_mask, 1, sizeof(pdump->dump_thread_id_mask));
		pdump->dump_thread_id_array_num = sapp_global_val->config.cpu.worker_threads;
		return 0;
	}

	memset(pdump->dump_thread_id_mask, 0, sizeof(pdump->dump_thread_id_mask));

	for(i = 0; i < pdump->dump_thread_id_array_num; i++){
		index = pdump->dump_thread_id_array[i];
		if(index >= SAPP_MAX_THREADS){
			sapp_log(30, ~0, ~0, "[Error]sapp.toml->PKT_DUMP->dump_thread_id value more than max CPU core number!");
			return -1;
		}else{
			pdump->dump_thread_id_mask[index] = 1;
		}
	}

	return 0;
}

/*
	C_router_vlan_id  I_router_vlan_id mac_flipping_enable
*/
static int parse_vlan_flipping_map_config(void)
{
	FILE *fp;
	char line_cont[MAX_INPUT];
	const char *filename = sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_cfg_file;
	sapp_vlan_flipping_map_t *vlan_map = sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_array;
	int vlan_map_num = 0;
	int i, ret;
	unsigned long long c_router_vlan_id, i_router_vlan_id, mac_flip_enable;

	fp = fopen(filename, "r");
	if(NULL == fp){
		sapp_log(30, ~0, ~0, "[Error]can't open sapp.toml->vlan_flipping_cfg_file:%s", filename);
		return -1;
	}

	while(fgets(line_cont, MAX_INPUT, fp)){
		if('#' == line_cont[0] || ' ' == line_cont[0] || '\r' == line_cont[0] || '\n' == line_cont[0]){
			continue;
		}

		ret = sscanf(line_cont, "%u %u %u", &c_router_vlan_id, &i_router_vlan_id, &mac_flip_enable);
		if(ret != 3){
			sapp_log(30, ~0, ~0, "[Error]parse sapp.toml->vlan_flipping_cfg_file:%s, line:%s error!", filename, line_cont);
			return -1;
		}
		if(c_router_vlan_id>= 4096 || i_router_vlan_id >= 4096){
			sapp_log(30, ~0, ~0, "[Error]parse sapp.toml->vlan_flipping_cfg_file:%s line:%s  error, vlan id must in range[1,4095]!", filename, line_cont);
			return -1;			
		}
		vlan_map[vlan_map_num].c_router_vlan_id = (unsigned short)c_router_vlan_id;
		vlan_map[vlan_map_num].i_router_vlan_id = (unsigned short)i_router_vlan_id;
		vlan_map[vlan_map_num].mac_flipping_enable = (short)mac_flip_enable;

		vlan_map_num++;
	}

	sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_num = vlan_map_num;

	if(0 == vlan_map_num){
		sapp_runtime_log(RLOG_LV_INFO, "parse vlan_flipping_cfg_file, no valid config!");
	}else{
		for(i = 0; i < vlan_map_num; i++){
			sapp_runtime_log(RLOG_LV_DEBUG, "vlan_flipping_cfg_file %d: c_router_vlan_id:%u, i_router_vlan_id:%u, mac_flipping_enable:%d", 
							i, vlan_map[i].c_router_vlan_id, vlan_map[i].i_router_vlan_id, vlan_map[i].mac_flipping_enable);
		}
	}

	return 0;
}


static int embed_layer_t_pton(char *config_val, embed_layer_t *result)
{
	enum addr_type_t addrtype;
	int i, j, ret, layer_index;
	const char *delim = "[] ";
	char *save_ptr;
	const char *layer_type_string;
	const char *layer_index_string;

	layer_type_string = strtok_r(config_val, delim, &save_ptr);
	layer_index_string = strtok_r(NULL, delim, &save_ptr);

	if(NULL == layer_type_string || NULL == layer_index_string ){
		return -1;
	}
	
	addrtype = addr_type_abbreviation_pton(layer_type_string);
	if(__ADDR_TYPE_MAX == addrtype){
		return -1;
	}

	memset(result, 0, sizeof(embed_layer_t));

	if('*' == layer_index_string[0]){
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			result->layer_type_index[addrtype][j] = 1;
		}
	}else{
		layer_index = atoi(layer_index_string);
		if(layer_index < 0 || layer_index >= (int)__ADDR_TYPE_MAX){
			return -1;
		}

		result->layer_type_index[addrtype][layer_index] = 1;
	}

	return 0;
}

/*
	return value pattern: 
	    addr_type_name[layer_index]
*/
static const char *embed_layer_t_ntop(const embed_layer_t *layer_st, char *result, int res_max_len)
{
	char addrtype_name_str[NAME_MAX] = {};
	char layer_index_str[NAME_MAX] = {};
	char one_layer_index_str[NAME_MAX];
	int i, j;

	memset(result, 0, res_max_len);
	
	for(i = __ADDR_TYPE_INIT + 1; i < __ADDR_TYPE_MAX; i++){
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			if(layer_st->layer_type_index[i][j] != 0){
				sprintf(addrtype_name_str, "%s", addr_type_abbreviation_ntop((enum addr_type_t)i));
				goto bingo;
			}
		}
	}

bingo:
	for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
		if(layer_st->layer_type_index[i][j] != 0){
			sprintf(one_layer_index_str, "%d,", j);
			strcat(layer_index_str, one_layer_index_str);
		}
	}	

	snprintf(result, res_max_len, "%s[%s]", addrtype_name_str, layer_index_str);
	
	return result;
}

static int update_asymmetric_addr_layer(embed_layer_t *result)
{
	int type_index, layer_index;

	for(type_index = 0; type_index < __ADDR_TYPE_MAX; type_index++){
		for(layer_index = 0; layer_index < SAPP_SUPPORT_LAYER_NUM_MAX; layer_index++){
			if(result->layer_type_index[type_index][layer_index] != 0){
				g_asymmetric_addr_layer_set.layer_type_index[type_index][layer_index] = 1;
			}
		}
	}

	return 0;
}

static int update_asymmetric_presence_layer(enum addr_type_t addrtype, embed_layer_t *under_layer, embed_layer_t *upper_layer)
{
	int i;

	g_asymmetric_presence_layer_set[addrtype].is_asymmetric_layer = 1;
	memcpy(&g_asymmetric_presence_layer_set[addrtype].under_layer, under_layer, sizeof(embed_layer_t));
	memcpy(&g_asymmetric_presence_layer_set[addrtype].upper_layer, upper_layer, sizeof(embed_layer_t));

	return 0;
}

/* 
    #pattern: asymmetric_layer_name[layer index]
    ethernet[1]
    mpls[*]
*/
static int parse_asymmetric_addr_layer_config(void)
{
	int i, j, ret, asymmetric_addr_layer_config_num = 0;
	FILE *fp;
	char line_cont[MAX_INPUT];
	embed_layer_t embed_layer;
	
	fp = fopen(sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_addr_layer_cfg_file, "r");
	if(NULL == fp){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]can't open sapp.toml->asymmetric_addr_layer_cfg_file:%s", 
				sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_addr_layer_cfg_file);
		return -1;
	}

	memset(&g_asymmetric_addr_layer_set, 0, sizeof(g_asymmetric_addr_layer_set));

	while(fgets(line_cont, MAX_INPUT, fp)){
		if('#' == line_cont[0] || ' ' == line_cont[0] || '\r' == line_cont[0] || '\n' == line_cont[0]){
			continue;
		}
		memset(&embed_layer, 0, sizeof(embed_layer));
		ret = embed_layer_t_pton(line_cont, &embed_layer);
		if(ret < 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]parse cfg_file:%s error, inlavid:%s", 
					sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_addr_layer_cfg_file,
					line_cont); 
			return -1;
		}

		update_asymmetric_addr_layer(&embed_layer);
		asymmetric_addr_layer_config_num++;
	}

	char one_layer_index_str[NAME_MAX];
	char debug_layer_index_str[NAME_MAX];
	
	for(i = __ADDR_TYPE_INIT + 1; i < __ADDR_TYPE_MAX; i++){
		memset(debug_layer_index_str, 0, sizeof(debug_layer_index_str));
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			if(g_asymmetric_addr_layer_set.layer_type_index[i][j] != 0){
				sprintf(one_layer_index_str, "%d,", j);
				strcat(debug_layer_index_str, one_layer_index_str);
			}
		}
		sapp_runtime_log(RLOG_LV_DEBUG, "asymmetric_addr_layer: %s:%s", 
					addr_type_abbreviation_ntop((enum addr_type_t)i),
					debug_layer_index_str);
	}

	return 0;
}




/*
    #pattern: asymmetric_layer_name  under_of_this_asymmetric_layer upper_of_this_asymmetric_layer
    vlan    ethernet[0]    ipv4[1]
*/
static int parse_asymmetric_presence_layer_config(void)
{
	int i, j, ret, asymmetric_presence_layer_config_num = 0;
	FILE *fp;
	char line_cont[MAX_INPUT];
	char layer_name[MAX_INPUT], under_layer_name[MAX_INPUT], upper_layer_name[MAX_INPUT];
	enum addr_type_t this_layer;
	embed_layer_t under_layer, upper_layer;
	
	fp = fopen(sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file, "r");
	if(NULL == fp){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]can't open sapp.toml->asymmetric_presence_layer_cfg_file:%s", 
				sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file);
		return -1;
	}

	memset(g_asymmetric_presence_layer_set, 0, sizeof(g_asymmetric_presence_layer_set));

	while(fgets(line_cont, MAX_INPUT, fp)){
		if('#' == line_cont[0] || ' ' == line_cont[0] || '\r' == line_cont[0] || '\n' == line_cont[0]){
			continue;
		}

		ret = sscanf(line_cont, "%s\t%s\t%s", layer_name,under_layer_name,upper_layer_name);
		if(ret != 3){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]parse sapp.toml->asymmetric_presence_layer_cfg_file:%s error, invalid config:%s", 
				sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file, line_cont);
			return -1;
		}

		this_layer = addr_type_abbreviation_pton(layer_name);
		if(__ADDR_TYPE_MAX == this_layer){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]parse cfg_file:%s error, inlavid:%s", 
					sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file,
					line_cont); 
			return -1;
		}

		ret = embed_layer_t_pton(under_layer_name, &under_layer);
		if(ret < 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]parse cfg_file:%s error, inlavid:%s", 
					sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file,
					line_cont); 
			return -1;
		}

		ret = embed_layer_t_pton(upper_layer_name, &upper_layer);
		if(ret < 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[Error]parse cfg_file:%s error, inlavid:%s", 
					sapp_global_val->config.packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file,
					line_cont); 
			return -1;
		}
		
		update_asymmetric_presence_layer(this_layer, &under_layer, &upper_layer);
		asymmetric_presence_layer_config_num++;
	}

	//////// debug print

	char under_layer_index_str[NAME_MAX];
	char upper_layer_index_str[NAME_MAX];	
	for(i = __ADDR_TYPE_INIT + 1; i < __ADDR_TYPE_MAX; i++){
		if(g_asymmetric_presence_layer_set[i].is_asymmetric_layer != 0){
			embed_layer_t_ntop(&g_asymmetric_presence_layer_set[i].under_layer, under_layer_index_str, NAME_MAX);
			embed_layer_t_ntop(&g_asymmetric_presence_layer_set[i].upper_layer, upper_layer_index_str, NAME_MAX);
			sapp_runtime_log(RLOG_LV_DEBUG, "asymmetric_presence_layer: %s, under_layer:%s, upperlayer:%s", 
						addr_type_abbreviation_ntop((enum addr_type_t)i),
						under_layer_index_str,
						upper_layer_index_str);
		}
	}
	

	return 0;
}


/* 配置格式转换, 如字符串类型转为int类型,便于程序处理 */
static int config_expression_convert(void)
{
	sapp_config_t *pconfig;
	const char *tmp_str;
	int ret;
	
	pconfig = &sapp_global_val->config;

	if(pconfig->cpu.bind_mask_array_num > 0){
		sapp_global_val->config.cpu.bind_mask = tomlc99_long_array_combination(pconfig->cpu.bind_mask_array, pconfig->cpu.bind_mask_array_num);
	}

	if(pconfig->stream.tcp.syn_mandatory != 0){
		sapp_global_val->individual_fixed.create_stream_mode = TCP_CTEAT_LINK_BYSYN;
	}else{
		sapp_global_val->individual_fixed.create_stream_mode = TCP_CTEAT_LINK_BYSYN | TCP_CTEAT_LINK_BYDATA;
	}

	/******************************  PACKET_IO  *******************************/

	/*
		net_connection_mode:
			0: don't send packet, only capture;
			1: parallel mode with single card;
			2: serial mode with two card;
			3: logic serial mode with G device.
	*/	
	tmp_str = pconfig->packet_io.depolyment_mode_str;
	if(strncasecmp(tmp_str, "mirror", strlen("mirror")) == 0){
		pconfig->packet_io.depolyment_mode_bin = DEPOLYMENT_MODE_MIRROR;
		sapp_global_val->individual_fixed.depolyment_mode_private = NET_CONN_PARALLEL;
	}else if(strncasecmp(tmp_str, "inline", strlen("inline")) == 0){
		pconfig->packet_io.depolyment_mode_bin = DEPOLYMENT_MODE_INLINE;
		sapp_global_val->individual_fixed.depolyment_mode_private = NET_CONN_SERIAL_GDEV;
	}else if(strncasecmp(tmp_str, "transparent", strlen("transparent")) == 0){
		pconfig->packet_io.depolyment_mode_bin = DEPOLYMENT_MODE_TRANSPARENT;
		sapp_global_val->individual_fixed.depolyment_mode_private = NET_CONN_SERIAL_2CARD;
	}else{
		sapp_log(30, ~0, ~0, "[Error]sapp.toml->PACKET_IO.depolyment.mode error, only support:%s!", "[mirror, inline, transparent]");
		return -1;
	}

	tmp_str = pconfig->packet_io.packet_io_tunnel.overlay_mode_string;
	if(strncasecmp(tmp_str, "none", strlen("none")) == 0){
		pconfig->packet_io.packet_io_tunnel.overlay_mode_bin = OVERLAY_MODE_NONE;
	}else if(strncasecmp(tmp_str, "vxlan", strlen("vxlan")) == 0){
		pconfig->packet_io.packet_io_tunnel.overlay_mode_bin = OVERLAY_MODE_VXLAN;
	}else{
		sapp_log(30, ~0, ~0, "[Error]sapp.toml->overlay_mode error, unsupport : %s", tmp_str); 
		return -1;
	}

	if(DEPOLYMENT_MODE_INLINE == pconfig->packet_io.depolyment_mode_bin){
		ret = parse_vlan_flipping_map_config();
		if(ret < 0){
			sapp_log(30, ~0, ~0, "[Error]sapp.toml->vlan_flipping_cfg_file parse error"); 
			return- 1;
		}

		ret = parse_asymmetric_addr_layer_config();
		if(ret < 0){
			sapp_log(30, ~0, ~0, "[Error]sapp.toml->vlan_flipping_cfg_file parse error"); 
			return- 1;
		}
		ret = parse_asymmetric_presence_layer_config();
		if(ret < 0){
			sapp_log(30, ~0, ~0, "[Error]sapp.toml->vlan_flipping_cfg_file parse error"); 
			return- 1;
		}	

		//todo, parse prune inject cfg file
	}
	
	tmp_str = pconfig->packet_io.internal.interface.type_str;
	if(strncasecmp(tmp_str, "pcap", strlen("pcap")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_PCAP_ONLINE;
	}else if(strncasecmp(tmp_str, "pag", strlen("pag")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_PAG;
	}else if(strncasecmp(tmp_str, "marsio", strlen("marsio")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_MARSIOV4;
	}else if(strncasecmp(tmp_str, "tun", strlen("tun")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_TUN;
	}else{
		sapp_log(30, ~0, ~0, "[Error]sapp.toml->type error, unsupport : %s", tmp_str); 
		return -1;
	}

	if(strncasecmp("sys_route", pconfig->packet_io.inject_pkt_mode_string, strlen("sys_route")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_STACK_3_LAYER;
	}else if(strncasecmp("vxlan_by_inline_device", pconfig->packet_io.inject_pkt_mode_string, strlen("vxlan_by_inline_device")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_GDEV;
	}else if(strncasecmp("raw_ethernet_single_gateway", pconfig->packet_io.inject_pkt_mode_string, strlen("raw_ethernet_single_gateway")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_STACK_2_LAYER_1_ROUTE;
	}else if(strncasecmp("raw_ethernet_multi_gateway", pconfig->packet_io.inject_pkt_mode_string, strlen("raw_ethernet_multi_gateway")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_STACK_2_LAYER_MUTI_ROUTE;
	}else{
	  	sapp_log(30, ~0, ~0, "[Error]sapp.toml->PACKET_IO.inject_pkt_mode error, only support:%s!", "[sys_route, vxlan_by_inline_device, raw_ethernet_single_gateway, raw_ethernet_multi_gateway]");
		return -1;		
	}

	if(strncasecmp(pconfig->packet_io.inject_pkt_mode_string, "raw_ethernet_single_gateway", strlen("raw_ethernet_single_gateway")) == 0){
		if(MESA_mac_pton(pconfig->packet_io.inject_mode_single_gateway_dst_mac_string, ':', pconfig->packet_io.inject_mode_single_gateway_dst_mac) < 0){
			sapp_log(30, ~0, ~0, "[Error]sapp.toml->[packet_io.feature]->inject_mode_single_gateway_dst_mac error: %s", pconfig->packet_io.inject_mode_single_gateway_dst_mac_string);
			return -1;	
		}

		if(MESA_get_dev_mac(pconfig->packet_io.inject_mode_single_gateway_device, (unsigned char *)pconfig->packet_io.inject_mode_single_gateway_src_mac) < 0){
			sapp_log(20, ~0, ~0, "[Warning]can't get sapp.toml->[packet_io.feature]->inject_mode_single_gateway_device: '%s' mac address", pconfig->packet_io.inject_mode_single_gateway_device);
			
			tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.feature", (char *)"inject_mode_single_gateway_src_mac", pconfig->packet_io.inject_mode_single_gateway_src_mac_string, sizeof(pconfig->packet_io.inject_mode_single_gateway_src_mac_string), "$");
			if('$' == pconfig->packet_io.inject_mode_single_gateway_src_mac_string[0]){
				sapp_log(30, ~0, ~0, "[Error]can't get local device '%s' mac address, and no valid inject_mode_single_gateway_src_mac", pconfig->packet_io.inject_mode_single_gateway_device);
				return -1;
			}
			if(MESA_mac_pton(pconfig->packet_io.inject_mode_single_gateway_src_mac_string, ':', pconfig->packet_io.inject_mode_single_gateway_src_mac) < 0){
				sapp_log(30, ~0, ~0, "[Error]sapp.toml->[packet_io.feature]->inject_mode_single_gateway_src_mac error: %s", pconfig->packet_io.inject_mode_single_gateway_src_mac_string);
				return -1;	
			}			
		}
	}

	tmp_str = pconfig->packet_io.external.interface.type_str;
	if(strncasecmp(tmp_str, "pcap", strlen("pcap")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_PCAP_ONLINE;
	}else if(strncasecmp(tmp_str, "pag", strlen("pag")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_PAG;
	}else if(strncasecmp(tmp_str, "marsio", strlen("marsio")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_MARSIOV4;
	}else if(strncasecmp(tmp_str, "tun", strlen("tun")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_TUN;
	}


	/******************************  STREAM  *******************************/
	struct tm ttm;
	time_t tt;
	if(sapp_global_val->config.stream.stream_id_base_time_str[0] == '\0'){
		sapp_log(20, ~0, ~0, "[Warning]sapp.toml->STREAM.stream_id_base_time is not set, use '1970-01-01 00:00:00' as default!");
		sapp_global_val->config.stream.stream_id_base_time_t = 0;
	}else{
		if(strptime(sapp_global_val->config.stream.stream_id_base_time_str, "%Y-%m-%d %H:%M:%S", &ttm) == NULL){
		  	sapp_log(30, ~0, ~0, "[Error]sapp.toml->STREAM.stream_id_base_time format error, must like '1970-01-01 01:02:03'");
			return -1;
		}
		if(mktime(&ttm) > time(NULL)){
		  	sapp_log(30, ~0, ~0, "[Error]sapp.toml->STREAM.stream_id_base_time value error, is after current system time!");
			return -1;
		}
		if(time(NULL) - mktime(&ttm) > 268435456L){
		  	sapp_log(30, ~0, ~0, "[Error]sapp.toml->STREAM.stream_id_base_time value error, sapp stream id support max time range is 8.5 year!");
			return -1;
		}
		sapp_global_val->config.stream.stream_id_base_time_t = mktime(&ttm);
	}

	/******************************  TOOLS   *******************************/
	if(strncasecmp(pconfig->tools.pkt_dump.mode_str, "storage" ,strlen("storage")) == 0){
		pconfig->tools.pkt_dump.mode_bin = PKT_DUMP_LOCAL_FILE;
	}else if(strncasecmp(pconfig->tools.pkt_dump.mode_str, "udp_socket" ,strlen("udp_socket")) == 0){
		pconfig->tools.pkt_dump.mode_bin = PKT_DUMP_UDP_SOCKET;
	}else{
		sapp_log(30, ~0, ~0, "[Error]TOOLS.PKT_DUMP.mode only support [storage, udp_socket]!");
		return -1;
	}

	if(pkt_dump_thread_id_convert() < 0){
		return -1;
	}

	return 0;
}

/*
	1: yes, go on!
	0: no,  exit.
*/
static int get_user_intention(void)
{
	char input_buf[MAX_INPUT];
	
	while(fgets(input_buf, sizeof(input_buf), stdin)){
		if(strncasecmp(input_buf, "y", 1) == 0){
			return 1;
		}else if(strncasecmp(input_buf, "n", 1) == 0){
			return 0;
		}else{
			sapp_log(30, ~0, ~0, "Please input 'y' or 'n' : "); 
			continue;
		}
	}

	return 1;
}


static inline void old_config_file_detect(const char *old_filename, const char *new_filename)
{
	if(is_file_exist(old_filename)){
		sapp_log(30, ~0, ~0, "[Error]This is sapp v4.0, detect obsolete config file:\"%s\"! please use \"%s\" instead!", old_filename, new_filename);
		if(is_file_exist(new_filename)){
			sapp_log(30, ~0, ~0, "You already have new config file:\"%s\", you must rename or delete obsolete file:\"%s\"!", new_filename, old_filename); 
			//sapp_log(30, ~0, ~0, "Are you sure you are using new config file? 'y' or 'n':");
			//if(0 == get_user_intention()){
				exit(1);
			//}			
		}else{
			//sapp_log(30, ~0, ~0, "Do you want to continue running, the sapp behavior is unpredictable! 'y' or 'n' : "); 
			//if(0 == get_user_intention()){
				sapp_log(30, ~0, ~0, "You should run ./sapp --sample-config to generate sapp.toml!");
				exit(1);
			//}
		}
	}
}


/*
	配置文件合法性、相关性检查.
	
	return value:
		 0: succ;
		-1: error, must exit!
*/
static int config_sanity_check(void)
{
	int cur_cpu_num;
	const char *tmp_str;
	const sapp_config_t *pconfig = &sapp_global_val->config;

	struct streaminfo_private phony_stream_pr;

	phony_stream_pr.layer_index = 0xF;
	assert(SAPP_SUPPORT_LAYER_NUM_MAX == phony_stream_pr.layer_index); /* 用于判断无意中修改了layer_index或SAPP_SUPPORT_LAYER_NUM_MAX, 两个变量不一致的情况 */
	if(SAPP_SUPPORT_LAYER_NUM_MAX != phony_stream_pr.layer_index){
		sapp_log(30, ~0, ~0, "[Error]SAPP_SUPPORT_LAYER_NUM_MAX is:%d, but streaminfo_private->layer_index max is:%d", SAPP_SUPPORT_LAYER_NUM_MAX, phony_stream_pr.layer_index); 
		return -1;
	}

	/*******************************  CPU  ********************************/
	cur_cpu_num = get_nprocs();
	if(cur_cpu_num < pconfig->cpu.worker_threads){
		printf("\033[33m[Warning]sapp.toml->CPU.worker_threads=%d more than current available processors:%d\033[0m\n", sapp_global_val->config.cpu.worker_threads, cur_cpu_num);		
		sapp_log(20, 0, ~0, "[Warning]sapp.toml->CPU.worker_threads=%d more than current available processors:%d", sapp_global_val->config.cpu.worker_threads, cur_cpu_num); 	
		sleep(1);
	}

	if((pconfig->cpu.bind_mask_array_num > 0) 
	 &&(pconfig->cpu.worker_threads + pconfig->cpu.send_only_threads_max_num != pconfig->cpu.bind_mask_array_num)){
		printf("\033[41m[Error]etc/sapp.toml->CPU->bind_mask value is not match etc/sapp.toml->CPU->worker_threads + CPU->send_only_threads_max!\033[0m\n");
		printf("\033[41m for example, worker_threads=4, send_only_threads_max=4, bind_mask should be [1,2,3,4,5,6,7,8].\033[0m\n");
		return -1;
	}

	/*******************************  STREAM  ******************************/
	if(pconfig->stream.tcp.inject.rst_num <= 0 || pconfig->stream.tcp.inject.rst_num >= 10){
		sapp_log(30, ~0, ~0, "[Error]sapp.toml->stream.tcp.inject.rst.number=%d, is Illegal!", pconfig->stream.tcp.inject.rst_num);
		return -1;
	}

	tmp_str = pconfig->packet_io.depolyment_mode_str;
	if((strncasecmp(tmp_str, "mirror", strlen("mirror")) != 0)
	  &&(strncasecmp(tmp_str, "inline", strlen("inline")) != 0)
	  &&(strncasecmp(tmp_str, "transparent", strlen("transparent")) != 0)
	  &&(strncasecmp(tmp_str, "dumpfile", strlen("dumpfile")) != 0)){
	  	printf("\033[1;31;40m[Error]sapp.toml->PACKET_IO.depolyment.mode error, only support:%s!\033[0m\n", "[mirror, inline, transparent, dumpfile]");
		return -1;
	}

	if(strncasecmp(tmp_str, "transparent", strlen("transparent")) == 0){
		if((pconfig->packet_io.internal.interface.name[0] == '\0')
		 ||(pconfig->packet_io.internal.interface.type_str[0] == '\0')){
			sapp_log(30, ~0, ~0, "depolyment_mode is transparent, must set internal interface parameters!");
			return -1;
		}
		if((pconfig->packet_io.external.interface.name[0] == '\0')
		 ||(pconfig->packet_io.external.interface.type_str[0] == '\0')){
			sapp_log(30, ~0, ~0, "depolyment_mode is transparent, must set external interface parameters!");
			return -1;
		}

		if(strncasecmp(pconfig->packet_io.internal.interface.type_str,
					   pconfig->packet_io.external.interface.type_str,
					   strlen(pconfig->packet_io.internal.interface.type_str)) != 0){
			sapp_log(30, ~0, ~0, "int transparent, internal and external interface type must be the same!");
			return -1;
		}
	}
	

	/*******************************  PKT_DUMP  ******************************/
	if(pconfig->tools.pkt_dump.dump_thread_id_array_num > pconfig->cpu.worker_threads){
		sapp_log(30, ~0, ~0, "[Error] TOOLS.PKT_DUMP.dump_thread_id_array items more than CPU.worker_threads!");
		return -1;
	}

	if((strncasecmp(pconfig->tools.pkt_dump.mode_str, "storage" ,strlen("storage")) != 0)
     && (strncasecmp(pconfig->tools.pkt_dump.mode_str, "udp_socket" ,strlen("udp_socket")) != 0)){
		sapp_log(30, ~0, ~0, "[Error]TOOLS.PKT_DUMP.mode only support [storage, udp_socket]!");
		return -1;
	}

	if(strncasecmp(pconfig->tools.pkt_dump.mode_str, "udp_socket" ,strlen("udp_socket")) == 0){
		if(pconfig->tools.pkt_dump.command_port <=0 || pconfig->tools.pkt_dump.command_port > 65535){
			sapp_log(30, ~0, ~0, "[Error] TOOLS.PKT_DUMP.command_port: %u invalid!", pconfig->tools.pkt_dump.command_port);
			return -1;
		}
	}	

	old_config_file_detect("./conf/main.conf", "./etc/sapp.toml");


	if(pconfig->protocol_feature.treat_vlan_as_mac_in_mac_enabled != 0){
		sapp_log(30, ~0, ~0, "[Warning]'treat_vlan_as_mac_in_mac' is enable, vlan packet will be treat as MAC_IN_MAC!");
		usleep(10000);
	}

	return 0;
}


/* 因为处理过程中,要写文件,log_handle必须先初始化 */
static void log_handle_init(void)
{
	void *lhand;
	MESA_handle_runtime_log_creation(sapp_global_val->config.profiling.log.local.log_conf_name);
	lhand = MESA_create_runtime_log_handle("./log/runtimelog", sapp_global_val->config.profiling.log.level);

	sapp_global_val->individual_fixed.log_handle = lhand;
}


void sapp_gval_init(void)
{
	int tseq;
	
	sapp_global_val = (sapp_global_t *)calloc(1, sizeof(sapp_global_t));
	sapp_global_val->individual_volatile = (sapp_gval_individual_volatile_t *)calloc(1, sizeof(sapp_gval_individual_volatile_t));

	for(tseq = 0; tseq < SAPP_MAX_THREADS; tseq++){
		sapp_global_val->mthread_volatile[tseq] = (sapp_gval_mthread_t *)calloc(1, sizeof(sapp_gval_mthread_t));
	}

	/* set default value, maybe not input by user or config file */
	snprintf(sapp_global_val->config.packet_io.pcap_dumpfile_name, NAME_MAX, "dumpfile");

	ABBR_CURRENT_TIME = time(NULL);
}


/* 读取配置文件sapp.toml, 本函数只Load, 不做解析和错误处理 */
int sapp_parse_config(void)
{
	int ret;
	int tmp_int;
	sapp_config_t *pconfig;
	char str_tmp[ARG_MAX];
	
	if(0 == is_file_exist(default_config_file)){
		special_usage();
		exit(1);
	}
	
	pconfig = &sapp_global_val->config;

	/*******************************  SYSTEM *********************************/
	ret = tomlc99_wrap_load_string_def(default_config_file, (char *)"SYSTEM", (char *)"instance_name", pconfig->system.instance_name, NAME_MAX, "sapp_v4.0");
	if(TOMLC99_RET_PATTERN_ERROR == ret){
		/* 首次解析判断如果是PATTERN_ERROR, 说明toml格式有问题, 不再继续解析 */
		sapp_log(30, ~0, ~0, "parse config file %s error!", default_config_file);
		exit(1);
	}

	/*******************************  CPU *********************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"CPU", (char *)"worker_threads", (int *)&pconfig->cpu.worker_threads, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"CPU", (char *)"send_only_threads_max", (int *)&pconfig->cpu.send_only_threads_max_num, 0);

	pconfig->cpu.bind_mask_array_num = SAPP_MAX_THREADS;

	tomlc99_wrap_load_long_array(default_config_file, (char *)"CPU", (char *)"bind_mask", pconfig->cpu.bind_mask_array, &pconfig->cpu.bind_mask_array_num);
	int tmp_bind_mask[SAPP_MAX_THREADS];
	ret = MESA_load_profile_uint_range(
		default_config_file, (char *)"CPU", (char *)"bind_mask",
		SAPP_MAX_THREADS, (unsigned int *)tmp_bind_mask);
	if(ret > 0)
	{
		pconfig->cpu.bind_mask_array_num = ret;
		for (int i = 0; i < ret; i++)
		{
			pconfig->cpu.bind_mask_array[i] = (long)tmp_bind_mask[i];
		}
	}
		/*******************************  MEM *********************************/
		tomlc99_wrap_load_int_def(default_config_file, (char *)"MEM", (char *)"dictator_enable", (int *)&pconfig->mem.dictator_enable, 1);
	
	/*******************************  PACKET_IO ******************************/

	/*******************************  packet_io.overlay_tunnel_definition ******************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"overlay_tunnel_definition", (char *)"create_mpls_anyway", &pconfig->packet_io.create_mpls_anyway, 0);
	tomlc99_wrap_load_string_def(default_config_file, (char *)"overlay_tunnel_definition", (char *)"vlan_flipping_cfg_file", pconfig->packet_io.packet_io_tunnel.vlan_flipping_cfg_file, PATH_MAX, "etc/vlan_flipping_map.conf");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"overlay_tunnel_definition", (char *)"asymmetric_addr_layer_cfg_file", pconfig->packet_io.packet_io_tunnel.asymmetric_addr_layer_cfg_file, PATH_MAX, "etc/asymmetric_addr_layer.conf");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"overlay_tunnel_definition", (char *)"asymmetric_presence_layer_cfg_file", pconfig->packet_io.packet_io_tunnel.asymmetric_presence_layer_cfg_file, PATH_MAX, "etc/asymmetric_presence_layer.conf");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"overlay_tunnel_definition", (char *)"prune_inject_layer_cfg_file", pconfig->packet_io.packet_io_tunnel.prune_inject_layer_cfg_file, PATH_MAX, "etc/prune_inject_layer.conf");

	tomlc99_wrap_load_string_def(default_config_file, (char *)"overlay_tunnel_definition", (char *)"overlay_mode", pconfig->packet_io.packet_io_tunnel.overlay_mode_string, NAME_MAX, "_no_default_");

	/*******************************  packet_io.feature ******************************/
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.feature", (char *)"BSD_packet_filter", str_tmp, NAME_MAX, "");
	if(str_tmp[0] != '\0'){
		pconfig->packet_io.input_bpf_filter = strdup(str_tmp);
	}
	tomlc99_wrap_load_int_def(default_config_file, (char *)"packet_io.feature", (char *)"inbound_route_dir", &pconfig->packet_io.inbound_route_dir, 0);
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.feature", (char *)"pcap_capture_direction", pconfig->packet_io.pcap_capture_direction, NAME_MAX, "in");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.feature", (char *)"inject_pkt_mode", pconfig->packet_io.inject_pkt_mode_string, NAME_MAX, "sys_route");
	if(strncasecmp(pconfig->packet_io.inject_pkt_mode_string, "raw_ethernet_single_gateway", strlen("raw_ethernet_single_gateway")) == 0){
		tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.feature", (char *)"inject_mode_single_gateway_device", pconfig->packet_io.inject_mode_single_gateway_device, NAME_MAX, "lo");
		tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.feature", (char *)"inject_mode_single_gateway_dst_mac", pconfig->packet_io.inject_mode_single_gateway_dst_mac_string, sizeof(pconfig->packet_io.inject_mode_single_gateway_dst_mac_string), "$");
	}
	tomlc99_wrap_load_int_def(default_config_file, (char *)"packet_io.feature", (char *)"inject_mode_inline_device_sport", &tmp_int, 54789);
	if(tmp_int <= 0 || tmp_int > 65535){
		sapp_log(30, ~0, ~0, "config parse error! invalid value of 'packet_io.feature.inject_mode_inline_device_sport %d'", tmp_int);
		return -1;
	}else{
		pconfig->packet_io.inject_mode_inline_device_sport = tmp_int;
	}
	
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.depolyment", (char *)"mode", pconfig->packet_io.depolyment_mode_str, NAME_MAX, "mirror");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.internal.interface", (char *)"type", pconfig->packet_io.internal.interface.type_str, NAME_MAX, "pcap");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.internal.interface", (char *)"name", pconfig->packet_io.internal.interface.name, NAME_MAX, "lo");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.external.interface", (char *)"type", pconfig->packet_io.external.interface.type_str, NAME_MAX, "pcap");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"packet_io.external.interface", (char *)"name", pconfig->packet_io.external.interface.name, NAME_MAX, "lo");
	tomlc99_wrap_load_int_def(default_config_file, (char *)"packet_io.polling", (char *)"enabled", &pconfig->packet_io.polling_enabled, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"packet_io.polling", (char *)"polling_priority", &pconfig->packet_io.polling_priority, 100);

	/*******************************  STREAM ******************************/
	tomlc99_wrap_load_string_def(default_config_file, (char *)"STREAM", (char *)"stream_id_base_time", pconfig->stream.stream_id_base_time_str, 32, "");

	/*******************************  STREAM.TCP ******************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"max", (int *)&pconfig->stream.tcp.max, 50000);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"timeout", (int *)&pconfig->stream.tcp.timeout, 60);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"syn_mandatory", (int *)&pconfig->stream.tcp.syn_mandatory, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"reorder_pkt_max", (int *)&pconfig->stream.tcp.reorder_pkt_max, 5);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"analyse_option_enabled", (int *)&pconfig->stream.tcp.analyse_option_enabled, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"tuple4_reuse_time_interval", (int *)&pconfig->stream.tcp.tuple4_reuse_time_interval, 30);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"meaningful_statistics_minimum_pkt", (int *)&pconfig->stream.tcp.meaningful_statistics_minimum_pkt, 3);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp", (char *)"meaningful_statistics_minimum_byte", (int *)&pconfig->stream.tcp.meaningful_statistics_minimum_byte, 5);
	
	
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject", (char *)"link_mss", (int *)&pconfig->stream.tcp.inject.link_mss, 1460);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject.rst", (char *)"auto_remedy", (int *)&pconfig->stream.tcp.inject.auto_remedy, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject.rst", (char *)"signature_enabled", (int *)&pconfig->stream.tcp.inject.rst_signature_enable, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject.rst", (char *)"signature_seed1", (int *)&pconfig->stream.tcp.inject.rst_signature_seed1, 65535);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject.rst", (char *)"signature_seed2", (int *)&pconfig->stream.tcp.inject.rst_signature_seed2, 13);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject.rst", (char *)"number", (int *)&pconfig->stream.tcp.inject.rst_num, 3);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.tcp.inject.rst", (char *)"remedy_kill_tcp_by_inline_device", &pconfig->stream.tcp.inject.remedy_kill_tcp_by_inline_device, 0);


	/*******************************  STREAM.UDP ******************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.udp", (char *)"max", (int *)&pconfig->stream.udp.max, 5000);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.udp", (char *)"timeout", (int *)&pconfig->stream.udp.timeout, 60);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.udp", (char *)"meaningful_statistics_minimum_pkt", (int *)&pconfig->stream.udp.meaningful_statistics_minimum_pkt, 3);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"stream.udp", (char *)"meaningful_statistics_minimum_byte", (int *)&pconfig->stream.udp.meaningful_statistics_minimum_byte, 5);
	

	/*******************************  PROFILING ******************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.pkt_latency", (char *)"enabled", (int *)&pconfig->profiling.pkt_latency_enabled, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.pkt_latency", (char *)"threshold", (int *)&pconfig->profiling.pkt_latency_threshold_in_us, 10000);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.sanity_check", (char *)"raw_pkt_broken_enabled", (int *)&pconfig->profiling.sanity_check_raw_pkt_broken_enabled, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.sanity_check", (char *)"symbol_conflict_enabled", (int *)&pconfig->profiling.sanity_check_symbol_conflict_enabled, 0);

	/*******************************  PROFILING.LOG ***************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.log", (char *)"level", (int *)&pconfig->profiling.log.level, 20);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.log", (char *)"interval", (int *)&pconfig->profiling.log.interval, 3);
	/*******************************  PROFILING.LOG.local **********************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.log.local", (char *)"enabled", (int *)&pconfig->profiling.log.local.enabled, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.log.local", (char *)"file_truncate_enabled", (int *)&pconfig->profiling.log.local.file_truncate_enabled, 1);
	tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.local", (char *)"log_file_name", pconfig->profiling.log.local.log_file_name, NAME_MAX, "fs2_sysinfo.log");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.local", (char *)"log_conf_name", pconfig->profiling.log.local.log_conf_name, NAME_MAX, "./etc/zlog.conf");
	/*******************************  PROFILING.LOG.remote **********************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.log.remote", (char *)"enabled", (int *)&pconfig->profiling.log.remote.enabled, 0);
	tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.remote", (char *)"server_ip", pconfig->profiling.log.remote.server_ip, INET_ADDRSTRLEN, "#");
	tomlc99_wrap_load_int_def(default_config_file, (char *)"profiling.log.remote", (char *)"server_port", (int *)&pconfig->profiling.log.remote.server_port, 0);
#if 0
	//tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.remote", (char *)"remote_send_out_type", pconfig->profiling.log.remote.remote_send_out_type, NAME_MAX, "field_stat2");
	/*******************************  PROFILING.LOG.remote.field_stat2 **********************/
	if(strncasecmp(pconfig->profiling.log.remote.remote_send_out_type, "field_stat2", strlen("field_stat2")) == 0){
		tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.remote.field_stat2", (char *)"app_name", pconfig->profiling.log.remote.field_stat2.app_name, NAME_MAX, "sapp");
		tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.remote.field_stat2", (char *)"metric_type", str_tmp, ARG_MAX, "default");
		if(strncasecmp(str_tmp, "default", strlen("default")) == 0){
			pconfig->profiling.log.remote.field_stat2.metrics_type = FS_METRIS_OUTPUT_DEFAULT;
		}else if(strncasecmp(str_tmp, "json", strlen("json")) == 0){
			pconfig->profiling.log.remote.field_stat2.metrics_type = FS_METRIS_OUTPUT_JSON;
		}else{
			sapp_log(30, ~0, ~0, "config parse error! invalid value of 'profiling.log.remote.field_stat2.metric_type'");
			return -1;
		}
	/*******************************  PROFILING.LOG.remote.line_protocol **********************/	
	}else if(strncasecmp(pconfig->profiling.log.remote.remote_send_out_type, "line_protocol", strlen("line_protocol")) == 0){
		//TODO, parse tags array
	}else{
		sapp_log(30, ~0, ~0, "config parse error! invalid value of 'profiling.log.remote.remote_send_out_type'");
		return -1;
	}
#else
	strncpy(pconfig->profiling.log.remote.remote_send_out_type, "field_stat2", strlen("field_stat2"));
	tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.remote.field_stat2", (char *)"app_name", pconfig->profiling.log.remote.field_stat2.app_name, NAME_MAX, "sapp");
		tomlc99_wrap_load_string_def(default_config_file, (char *)"profiling.log.remote.field_stat2", (char *)"metric_type", str_tmp, ARG_MAX, "default");
		if(strncasecmp(str_tmp, "default", strlen("default")) == 0){
			pconfig->profiling.log.remote.field_stat2.metrics_type = FS_METRIS_OUTPUT_DEFAULT;
		}else if(strncasecmp(str_tmp, "json", strlen("json")) == 0){
			pconfig->profiling.log.remote.field_stat2.metrics_type = FS_METRIS_OUTPUT_JSON;
		}else{
			sapp_log(30, ~0, ~0, "config parse error! invalid value of 'profiling.log.remote.field_stat2.metric_type'");
			return -1;
		}
#endif
	/************************  PROTOCOL_FEATURE **********************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"ipv6_decapsulation_enabled", (int *)&pconfig->protocol_feature.ipv6_decapsulation_enabled, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"ipv6_send_packet_enabled", (int *)&pconfig->protocol_feature.ipv6_send_packet_enabled, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"tcp_drop_pure_ack_pkt", (int *)&pconfig->protocol_feature.tcp_drop_pure_ack_pkt, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"tcp_syn_option_parse_enabled", (int *)&pconfig->protocol_feature.tcp_syn_option_parse_enabled, 1);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"skip_not_ip_layer_over_eth", (int *)&pconfig->protocol_feature.skip_not_ip_layer_over_eth, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"treat_vlan_as_mac_in_mac", (int *)&pconfig->protocol_feature.treat_vlan_as_mac_in_mac_enabled, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"PROTOCOL_FEATURE", (char *)"reverse_ethernet_addr", (int *)&pconfig->protocol_feature.reverse_ethernet_addr_enabled, 1);

	/*******************************  TOOLS **********************************/
	tomlc99_wrap_load_int_def(default_config_file, (char *)"tools.signal_handler", (char *)"signal", (int *)&pconfig->tools.signal_handler.signal, 0);

	tomlc99_wrap_load_int_def(default_config_file, (char *)"tools.pkt_dump", (char *)"enabled", (int *)&pconfig->tools.pkt_dump.enabled, 0);
	tomlc99_wrap_load_string_def(default_config_file, (char *)"tools.pkt_dump", (char *)"mode", pconfig->tools.pkt_dump.mode_str, NAME_MAX, "udp_socket");
	tomlc99_wrap_load_string_def(default_config_file, (char *)"tools.pkt_dump", (char *)"BSD_packet_filter", str_tmp, ARG_MAX, "");
	if(str_tmp[0] != '\0'){
		pconfig->tools.pkt_dump.bpf_filter = strdup(str_tmp);
	}

	tomlc99_wrap_load_int_def(default_config_file, (char *)"tools.pkt_dump.threads", (char *)"all_threads_enabled", &pconfig->tools.pkt_dump.dump_all_thread_enabled, 0);
	if(0 == pconfig->tools.pkt_dump.dump_all_thread_enabled){
		pconfig->tools.pkt_dump.dump_thread_id_array_num = SAPP_MAX_THREADS;
		tomlc99_wrap_load_int_array(default_config_file, (char *)"tools.pkt_dump.threads", (char *)"dump_thread_id", pconfig->tools.pkt_dump.dump_thread_id_array, &pconfig->tools.pkt_dump.dump_thread_id_array_num);
	}
	
	tomlc99_wrap_load_int_def(default_config_file, (char *)"tools.pkt_dump.udp", (char *)"command_port", (int *)&pconfig->tools.pkt_dump.command_port, 0);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"tools.pkt_dump.udp", (char *)"pkt_dump_ratio", (int *)&pconfig->tools.pkt_dump.pkt_dump_ratio, 30);

	tomlc99_wrap_load_string_def(default_config_file, (char *)"tools.pkt_dump.storage", (char *)"path", str_tmp, ARG_MAX, "/dev/shm/pkt_dump");
	pconfig->tools.pkt_dump.storge_path = strdup(str_tmp);
	tomlc99_wrap_load_int_def(default_config_file, (char *)"tools.pkt_dump.storage", (char *)"file_size_max_per_thread", (int *)&pconfig->tools.pkt_dump.file_size_max_per_thread, 1000);

	/*************************** SPECIAL_CONFIG_LINK *************************/
	tomlc99_wrap_load_string_def(default_config_file, (char *)"SPECIAL_CONFIG_LINK", (char *)"project_list_path", str_tmp, ARG_MAX, "./etc/project_list.conf");
	if(str_tmp[0] != '\0'){
		pconfig->special_conf_link.project_list_path = strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(default_config_file, (char *)"SPECIAL_CONFIG_LINK", (char *)"plugin_path", str_tmp, ARG_MAX, "./etc/plugin.conf");
	if(str_tmp[0] != '\0'){
		pconfig->special_conf_link.plugin_path = strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(default_config_file, (char *)"SPECIAL_CONFIG_LINK", (char *)"entrylist_path", str_tmp, ARG_MAX, "./etc/entrylist.conf");
	if(str_tmp[0] != '\0'){
		pconfig->special_conf_link.entrylist_path = strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(default_config_file, (char *)"SPECIAL_CONFIG_LINK", (char *)"send_raw_pkt_path", str_tmp, ARG_MAX, "./etc/send_raw_pkt.conf");
	if(str_tmp[0] != '\0'){
		pconfig->special_conf_link.send_raw_pkt_path = strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(default_config_file, (char *)"SPECIAL_CONFIG_LINK", (char *)"vxlan_sport_service_map_path", str_tmp, ARG_MAX, "./etc/vxlan_sport_service_map.conf");
	if(str_tmp[0] != '\0'){
		pconfig->special_conf_link.vxlan_sport_service_map_path = strdup(str_tmp);
	}

	log_handle_init();

	if(config_sanity_check() < 0){
		exit(1);
	}

	if(config_expression_convert() < 0){
		exit(1);
	}

	sapp_log(10, 10, 10, "config parse success!");
	
	return 0;
}

/* init breakpad_mini */
void sapp_init_breakpad_mini(void)
{
#ifdef GIT_VERSION
	__attribute__((__used__)) const char *sapp_git_ver = GIT_VERSION;
#else
	 const char * sapp_git_ver = "sapp_version_unkonw"
#endif
	struct breakpad_instance * g_breakpad = breakpad_init(default_config_file, "breakpad", sapp_global_val->individual_fixed.log_handle,  sapp_git_ver);
	if(g_breakpad == NULL){exit(-1);}
	sapp_global_val->individual_fixed.breakpad = g_breakpad;
	return;
}

void sapp_segv_generate()
{
	breakpad_segv_generate();
}

#ifdef __cplusplus
}
#endif


