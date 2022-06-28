INC=-I/opt/MESA/include 
INC+=-I/opt/MESA/include/MESA
INC+=-I/opt/MESA/include/MESA/stream_inc


LIBS=-L/opt/MESA/lib
LIBS+=-lgtest -lMESA_handle_logger -lpthread -lsapp_benchmark

all:gtest_sapp_by_benchmark

gtest_sapp_by_benchmark:test_function_common.cpp
	./auto_gen_test_functions.sh
	g++ -o $@ $^ auto_gen_test_functions.cpp  -g -std=c++11 $(INC) $(LIBS)

clean:
	rm -f gtest_sapp_by_benchmark *.o
