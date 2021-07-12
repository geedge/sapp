all:test_dpdk_hash.so

test_dpdk_hash.o:test_dpdk_hash.c
	gcc -c -o $@ -fPIC $^ -I./include -I/opt/MESA/include/MESA

test_dpdk_hash.so:test_dpdk_hash.o
	gcc -o $@ -fPIC -shared $^
