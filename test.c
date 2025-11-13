#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main() {
	FILE *fp = fopen("./malware", "w");
	FILE *fd = fopen("./no_malware", "w");
	fwrite("This is malware", 1, 16, fp);
	fwrite("This is not malware", 1, 24, fd);
	fclose(fd);
	fclose(fp);
	return 0;
}