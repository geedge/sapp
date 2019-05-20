#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "toml.h"
#include "tomlc99_wrap.h"

static const char *filename = "test.toml";

static void test_read_int(void)
{
	int ret;
	int port;
	
	ret = tomlc99_wrap_load_int_def(filename, "server.foo", "port", &port, 0);
	if(ret < 0){
		printf("read [server.foo]->port error!\n");
	}else{
		printf("read [server.foo]->port succ, port=%d\n", port);
	}

	ret = tomlc99_wrap_load_int_def(filename, "server.foo.bar", "port", &port, 0);
	if(ret < 0){
		printf("read [server.foo.bar]->port error!\n");
	}else{
		printf("read [server.foo.bar]->port succ, port=%d\n", port);
	}
	
}

static void test_read_int_array(void)
{
	int i, ret;
	int mask[256];
	int num = 256;
	int comb_int_val;
	
	ret = tomlc99_wrap_load_int_array(filename, "server", "bind_mask", mask, &num);
	if(ret < 0){
		printf("read [server]->bind_mask error!\n");
	}else{
		printf("read [server]->bind_mask succ: \n");
		printf("[ ");
		for(i = 0; i < num; i++){
			printf("%d ", mask[i]);
		}
		printf("]\n");
	}

	comb_int_val = tomlc99_int_array_combination(mask, num);

	printf("bind_mask combination value is:0x%x\n", comb_int_val);
}


static void test_read_string(void)
{
	int ret;
	char str_val[256];

	ret = tomlc99_wrap_load_string_def(filename, "server", "ip", str_val, sizeof(str_val), "#");
	if(ret < 0){
		printf("read [server]->ip error!\n");
	}else{
		printf("read [server]->ip succ, ip=%s\n", str_val);
	}
	
	ret = tomlc99_wrap_load_string_def(filename, "server.foo", "ip", str_val, sizeof(str_val), "#");
	if(ret < 0){
		printf("read [server.foo]->ip error!\n");
	}else{
		printf("read [server.foo]->ip succ, ip=%s\n", str_val);
	}

	ret = tomlc99_wrap_load_string_def(filename, "server.foo.bar", "ip", str_val, sizeof(str_val), "#");
	if(ret < 0){
		printf("read [server.foo.bar]->ip error!\n");
	}else{
		printf("read [server.foo.bar]->ip succ, ip=%s\n", str_val);
	}
	
}


static void api_test(void)
{
	FILE* fp;
    toml_table_t* conf;
    toml_table_t* server;
    const char* raw;
    char* host;
    int64_t port;
    char errbuf[200];

    /* open file and parse */
    if (0 == (fp = fopen(filename, "r"))) {
        perror("fopen");
	exit(1);
    }
    conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    if (0 == conf) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
	exit(1);
    }

    /* locate the [server] table */
    if (0 == (server = toml_table_in(conf, "server"))) {
        fprintf(stderr, "ERROR: missing [server]\n");
	toml_free(conf);
	exit(1);
    }

    /* extract host config value */
    if (0 == (raw = toml_raw_in(server, "host"))) {
        fprintf(stderr, "ERROR: missing 'host' in [server]\n");
	toml_free(conf);
	exit(1);
    }
    if (toml_rtos(raw, &host)) {
        fprintf(stderr, "ERROR: bad value in 'host'\n");
	toml_free(conf);
	exit(1);
    }

    /* extract port config value */
    if (0 == (raw = toml_raw_in(server, "port"))) {
        fprintf(stderr, "ERROR: missing 'port' in [server]\n");
	free(host);
	toml_free(conf);
	exit(1);
    }
    if (toml_rtoi(raw, &port)) {
        fprintf(stderr, "ERROR: bad value in 'port'\n");
        free(host);			
	toml_free(conf);
	exit(1);
    }

    /* done with conf */
    toml_free(conf);

    /* use host and port */
	printf("get config host:%s\n", host);
	printf("get config port:%ld\n", port);

    /* clean up */
    free(host);

}

int main()
{
	api_test();
	test_read_int();
	test_read_int_array();
	test_read_string();

	return 0;
}

