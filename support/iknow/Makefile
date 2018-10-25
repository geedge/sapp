all:
	cd src; $(MAKE);
	cd example; $(MAKE);
	cp lib/libiknow.a ../../lib/;

clean:
	cd src; $(MAKE) clean;
	cd example; $(MAKE) clean;
	rm -f lib/*;
