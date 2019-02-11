
.PHONY: all install clean distclean

all:
	make -C src

install:

	./install.pl

clean:
	make -C src clean

distclean:
	make -C src distclean

