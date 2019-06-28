#ifndef harddns_proxy_h
#define harddns_proxy_h

#include <unistd.h>
#include <sys/time.h>
#include <map>
#include <string>
#include <utility>
#include "dnshttps.h"


namespace harddns {

class doh_proxy {

	int d_sock{-1};

	int d_af{0};

	struct cache_elem_t {
		std::string rdata;
		time_t valid_until;
	};

	std::map<std::pair<std::string, int>, cache_elem_t> d_rr_cache;

	void cache_insert(const std::string &, int, const std::string &, uint32_t);

	bool cache_lookup(const std::string &, int, std::map<std::string, std::string> &, uint32_t &);

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

	const char *why() { return d_err.c_str(); }

};

} // namespace

#endif

