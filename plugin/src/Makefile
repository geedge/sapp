
CC	= gcc
CFLAGS	+= -g -Wall -fPIC 
CFLAGS  += $(OPTFLAGS)
OBJECTS =  plugin_proc.o plugin.o plugin_platform.o plugin_protocol.o plugin_business.o 
TARGET	= plugctrl.a

INCS	= -I../inc 
INCS	+=-I../../include
INCS	+=-I../../include/net
INCS	+=-I/usr/include/MESA
INCS	+=-I/opt/MESA/include/MESA
LIB	= 

LIBPATH	+= ../lib

.cpp.o:  
	$(CC) -c -o $@ $(CFLAGS) $(INCS) $<

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(INCS) $<

.PHONY: all clean 
all:$(SUPPORT) $(TARGET)
$(TARGET):$(OBJECTS)
#$(TARGET):$(OBJECTS) $(LIB)
	ar -rs $(TARGET) $^
	cp $(TARGET) $(LIBPATH)
	
plugin_proc.o:plugin_proc.c
plugin.o:plugin.c
plugin_platform.o:plugin_platform.c
plugin_protocol.o:plugin_protocol.c
plugin_business.o:plugin_business.c


clean:
	rm -f $(TARGET)	$(OBJECTS) *.a

