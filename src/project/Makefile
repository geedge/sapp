#opt: OPTFLAGS = -O2
#export OPTFLAGS

#CC		= g++
#CCC		= g++
CFLAGS      	+= -Wall
CFLAGS		+= -fPIC -D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
CFLAGS		+= $(OPTFLAGS)
CFLAGS		+= -DPLATFORM_NSDPF_PAPP=1

LIBPATH = ../lib

H_DIR += $(INC)   
H_DIR += -I../../include/
H_DIR += -I../../include/public
H_DIR += -I../../include/private
H_DIR += -I../../include/support
H_DIR += -I/opt/MESA/include/MESA

TARGET = libproject.a

OBJS= project_requirement.o  
#terminal_tag.o 
OBJS+= raw_ip_frag_list.o  

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

all: $(TARGET)

$(TARGET): $(OBJS)
	rm -f $@ ;ar -r $@ $^; 
	cp $(TARGET) $(LIBPATH) 
clean:
	rm -f *.o $(TARGET)  *~

opt:
	$(MAKE) all
