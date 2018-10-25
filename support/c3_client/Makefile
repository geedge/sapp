CC = g++
CPP = g++

#DATE=$(shell date +%Y-%m-%d_%H:%M:%S)
DATE=$(shell cat version)
#CFLAGS = -g -Wall -DPROGRAM_DATE=\"$(DATE)\" -I./include -DNOTIME -DCONTROL_CONVERGE -D_GNU_SOURCE -DLINUX -DLinux -D__LITTLE_ENDIAN_BITFIELD -DPERMORMANCE_DEBUG -DPERFORMANCE_RULE_COUNT=100 -DVEVIFY_ID_ENABLE -DALWAYS_LOCK -fPIC 
CFLAGS = -g -Wall -DPROGRAM_DATE=\"$(DATE)\" -I./include -DNOTIME -DCONTROL_CONVERGE -D_GNU_SOURCE -DLINUX -DLinux -D__LITTLE_ENDIAN_BITFIELD -DVEVIFY_ID_ENABLE -DALWAYS_LOCK -fPIC 
#-DDEBUG_STRATEGY 
#-DHASH_MUTEX_ENABLE
LDFLAGS = -rdynamic 
LIBS = -L./ -L./lib/ -L/usr/local/lib/  -lpthread -ldl

#TARGET=libgrule.a
TARGET=c3client 
DYNAMIC_TARGET=libc3client.so
STATIC_TARGET=libc3client.a
all: $(TARGET) $(DYNAMIC_TARGET) $(STATIC_TARGET)

#debug_client: 

OBJECTS= alloc.o ccchdr.o efd_eventfd.o grule.o c3client.o main.o util.o ruleread.o

$(STATIC_TARGET): $(OBJECTS)
	ar -cr -o $@ $^;
	cp $@ ../../lib/;

$(DYNAMIC_TARGET): $(OBJECTS)
	$(CPP) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^;
	cp $@ ../../lib/;


$(TARGET): $(OBJECTS)
	#cd route ; make
	ar crsv libgrule.a $^
	$(CPP) $(CFLAGS) $(LDFLAGS) $(LIBS)  -o $@ $^  
#	cp $(TARGET) ../lib/

.c.o:
	$(CC) $(CFLAGS) -c -fPIC $<
.cpp.o:
	$(CPP) $(CFLAGS) -c -fPIC $<
.cc.o:
	$(CPP) $(CFLAGS) -c -fPIC $<


clean:
	rm *.a *.so *.o $(TARGET)  -f

install:
	cp c3client rule.conf* /home/ict/run_dir/c3client/ 

