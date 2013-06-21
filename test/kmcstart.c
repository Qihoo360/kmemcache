#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "util.h"

/*
 * argv[0]: command
 * argv[1]: for detail output
 * argv[2]: kmemcache.ko path
 * argv[3]: umemcached command
 * argv[4]: args of umemcached
 */
int main(int argc, char *argv[])
{
	assert(argc > 4);

	if (!strcmp(argv[1], "0"))
		close_terminal();

	start_kmc_server(argv + 2);

	return 0;
}
