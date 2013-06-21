#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

/*
 * argv[0]: command
 * argv[1]: for detail output
 */
int main(int argc, char *argv[])
{
	if (argc >= 2 && !strcmp(argv[1], "0"))
		close_terminal();

	stop_kmc_server(NULL);

	return 0;
}
