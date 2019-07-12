#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdio>
#include <cstring>


using namespace std;

int main(int argc, char **argv)
{

	char buf[256] = {0};
	addrinfo *res = nullptr, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
//	hints.ai_family = AF_ANY;

	for (;argc > 1;) {
		const char *name = argv[--argc];
		printf("resolving %s\n", name);
		getaddrinfo(name, "", &hints, &res);
		hostent *he = gethostbyname(name);
		for (;res; res = res->ai_next) {
			memset(buf, 0, sizeof(buf));
			if (res->ai_family == AF_INET)
				inet_ntop(res->ai_family, &((sockaddr_in *)res->ai_addr)->sin_addr, buf, sizeof(buf));
			else
				inet_ntop(res->ai_family, &((sockaddr_in6 *)res->ai_addr)->sin6_addr, buf, sizeof(buf));
			printf("gai: %d %s %s\n", res->ai_family, buf, res->ai_canonname?res->ai_canonname:"no canon");
		}

		char **aliases = he->h_aliases;
		for (;*aliases; ++aliases) {
			printf("he: %s\n", *aliases);
		}
	}

	return 0;
}

