
CXX=c++
INC=
CXXFLAGS=-c -Wall -O2 -std=c++11 -pedantic -fPIC -fsigned-char
LIBS=-lcrypto -lssl

# If you have openssl or libressl with TLS1.3 support
# (openssl since 1.1.1, you should add this in order to
# benefit from faster TLS handshakes.
# You also need to install and set apropriate path's for OSX (Darwin)
#SSL_PATH=/opt/ssl/openssl-1.1.1
#DEFS+=-I$(SSL_PATH)/include
#LIBS+=-L$(SSL_PATH)/lib

# Not necessary for OSX
#LIBS+=-Wl,--rpath=$(SSL_PATH)/lib


.PHONY: all clean distclean

ifeq ($(shell uname), Linux)

# since Linux kernel 4.11
DEFS+=-DTCP_FASTOPEN_CONNECT=30

all: build build/harddnsd build/libnss_harddns.so

else

all: build build/harddnsd

endif


build:
	mkdir build || true

build/libnss_harddns.so: build/nss.o build/ssl.o build/nss-init.o build/init.o build/config.o build/dnshttps.o build/misc.o build/base64.o
	$(CXX) -pie -shared -Wl,-soname,libnss_harddns.so $^ -o $@ $(LIBS)

build/harddnsd: build/ssl.o build/init.o build/config.o build/dnshttps.o build/proxy.o build/misc.o build/main.o build/base64.o
	$(CXX) -pie $^ -o $@ $(LIBS)

build/test: build/nss.o build/ssl.o build/init.o build/nss-init.o build/config.o build/dnshttps.o
	$(CXX) -shared -pie $^ -o $@ $(LIBS)


build/nss.o: nss.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/dnshttps.o: dnshttps.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/config.o: config.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/ssl.o: ssl.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/init.o: init.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/nss-init.o: nss-init.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/proxy.o: proxy.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/misc.o: misc.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/base64.o: base64.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@

build/main.o: main.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@


clean:
	rm -f build/*.o

distclean: clean
	rm -rf build

