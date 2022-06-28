INC=-I/opt/MESA/include 
INC+=-I/opt/MESA/include/MESA
INC+=-I/opt/MESA/include/MESA/stream_inc


LIBS=-L/opt/MESA/lib
LIBS+=-lgtest -lMESA_handle_logger -lpthread -lsapp_benchmark

all:test_sapp_benchmark_gtest

test_sapp_benchmark_gtest:test_sapp_benchmark_gtest_main.cpp 
	./auto_gen_gtest_functions.sh
	g++ -o $@ $^ auto_gen_gtest_functions.cpp -g -std=c++11 $(INC) $(LIBS)

clean:
	rm -f test_sapp_benchmark_gtest *.o
