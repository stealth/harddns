
#ifndef harddns_base64_h
#define harddns_base64_h

#include <sys/types.h>
#include <string>

namespace harddns {

std::string &b64url_encode(const std::string&, std::string&);

std::string &b64url_encode(const char *, size_t, std::string&);


}

#endif

