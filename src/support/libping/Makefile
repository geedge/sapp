all:
	cd src/support/MESA_socket_wrap; $(MAKE);
	cd src; $(MAKE);
	cd test; $(MAKE);

clean:
	cd src; $(MAKE) clean;
	cd test; $(MAKE) clean;
	cd src/support/MESA_socket_wrap; $(MAKE) clean;
	rm -f lib/*;

install:
	cp lib/libping.so /opt/MESA/lib
