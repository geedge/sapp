obj-m := sapp_tun_bridge_kmodule.o

modules-objs:= sapp_tun_bridge_kmodule.o

KDIR := /lib/modules/`uname -r`/build

PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o  *.ko *.mod.c .tmp_versions