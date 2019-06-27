#ifndef harddns_proxy_h
#define harddns_proxy_h

#include <unistd.h>
#include <string>
#include "dnshttps.h"


namespace harddns {

class doh_proxy {

	int d_sock{-1};

	int d_af{0};

	// As the dnshttp object we use the globally exported 'dns'
	// as used for the NSS module

	std::string d_err{""};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		d_err = "doh_proxy::";
		d_err += msg;
		if (errno) {
			d_err += ":";
			d_err += strerror(errno);
		}
		return r;
	}


public:

	doh_proxy()
	{
	}

	virtual ~doh_proxy()
	{
		::close(d_sock);
	}

	int init(const std::string &, const std::string &);

	int loop();

};

} // namespace

#endif

