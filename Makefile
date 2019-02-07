CXX=c++
DEF=
INC=
CXXFLAGS=-c -Wall -O2 -std=c++11 -pedantic -fPIC
LIB=-lcrypto -lssl

all: harddns

harddns: nss.o ssl.o init.o config.o dnshttps.o
	$(CXX) -pie -shared -Wl,-soname,libnss_harddns.so nss.o ssl.o init.o config.o dnshttps.o -o libnss_harddns.so $(LIB)

test: nss.o ssl.o init.o config.o dnshttps.o
	$(CXX) -shared -pie nss.o ssl.o init.o config.o dnshttps.o -o test $(LIB)


nss.o: nss.cc
	$(CXX) $(DEF) $(INC) $(CXXFLAGS) nss.cc

dnshttps.o: dnshttps.cc
	$(CXX) $(DEF) $(INC) $(CXXFLAGS) dnshttps.cc

config.o: config.cc
	$(CXX) $(DEF) $(INC) $(CXXFLAGS) config.cc

ssl.o: ssl.cc
	$(CXX) $(DEF) $(INC) $(CXXFLAGS) ssl.cc

init.o: init.cc
	$(CXX) $(DEF) $(INC) $(CXXFLAGS) init.cc

clean:
	rm -f *.o *.so

