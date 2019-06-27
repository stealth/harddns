#include "config.h"
#include "proxy.h"
#include "init.h"


using namespace std;
using namespace harddns;


int main(int argc, char **argv)
{

	harddns_init();


	doh_proxy doh;

	doh.init("127.0.0.1", "53");
	doh.loop();

	harddns_fini();

	return 0;
}

