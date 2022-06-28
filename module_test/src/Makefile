all:
	$(MAKE) -f Makefile_v4

clean:
	rm -rf *.o  *.so gtest_sapp_v3 gtest_sapp_v4  build/*

#version 3.0
install3:
	cp gtest_sapp_v3 /home/lijia/run/benchmark_v3/
	cp gtest_sapp.so /home/lijia/run/benchmark_v3/plug/business/gtest_sapp/gtest_sapp.so

#version 4.0
install:
	$(MAKE) -f Makefile_v4 install

install4:
	$(MAKE) -f Makefile_v4 install

#benchmark
installb:
	cp sapp_benchmark.so ../sapp_benchmark/plug/business/sapp_benchmark
