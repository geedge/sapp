CC	= gcc
CFLAGS	= -g -Wall -fPIC 
CFLAGS	+= -D__FAVOR_BSD=1 -D__USE_MISC=1 -D_GNU_SOURCE=1
CFLAGS  += $(OPTFLAGS)
OBJECTS = MESA_path_trace.o 
MODULES	=  
TARGET	= MESA_path_trace.so

INCS	= -I ../../include 
INCS	+= -I ../../include/net
INCS	+= -I ../../dealpkt
INCS	+= -I /usr/include/MESA
INCS	+= -I../../include/stream_inc


.PHONY: all clean 
all: $(TARGET)
$(TARGET):$(OBJECTS)
	$(CC) -o $(TARGET) -shared -fPIC $(CFLAGS) $(OBJECTS) $(MODULES)
	cp $@ ../../plug/business/MESA_path_trace/
	cp MESA_path_trace.inf ../../plug/business/MESA_path_trace/
	
MESA_path_trace.o:MESA_path_trace.c
	$(CC) -c -o $@ $(CFLAGS) -I. $(INCS) $<

clean:
	rm -f $(TARGET)	$(OBJECTS) 

