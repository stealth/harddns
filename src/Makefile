
CXX=c++
INC=
CXXFLAGS=-c -Wall -O2 -std=c++11 -pedantic -fPIC
LIBS=-lcrypto -lssl

# If you have openssl or libressl with TLS1.3 support
# (openssl since 1.1.1, you should add this in order to
# benefit from faster TLS handshakes
#DEFS+=-I/opt/ssl/openssl-1.1.1/include
#LIBS+=-L/opt/ssl/openssl-1.1.1/lib
#LIBS+=-Wl,--rpath=/opt/ssl/openssl-1.1.1/lib

# since Linux kernel 4.11
DEFS+=-DTCP_FASTOPEN_CONNECT=30

.PHONY: all clean distclean

all: build build/harddnsd build/libnss_harddns.so

build:
	mkdir build || true

build/libnss_harddns.so: build/nss.o build/ssl.o build/nss-init.o build/init.o build/config.o build/dnshttps.o
	$(CXX) -pie -shared -Wl,-soname,libnss_harddns.so $^ -o $@ $(LIBS)

build/harddnsd: build/ssl.o build/init.o build/config.o build/dnshttps.o build/proxy.o build/misc.o build/main.o
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

build/main.o: main.cc
	$(CXX) $(DEFS) $(INC) $(CXXFLAGS) $^ -o $@


clean:
	rm -f build/*.o

distclean: clean
	rm -rf build

