
// glue code to make harddns inited for the NSS DSO load

#include "init.h"


extern "C" void harddns_nss_init() __attribute__((constructor));
extern "C" void harddns_nss_init()
{
	harddns_init();
}


extern "C" void harddns_nss_fini() __attribute__((destructor));
extern "C" void harddns_nss_fini()
{
	harddns_fini();
}

