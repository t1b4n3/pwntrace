#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
	int fd = open("text.txt", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

	write(fd, "Hello world from a test process\n", 32);
	char buffer[0x30];
	read(fd, buffer, 0x29);
	//puts(buffer);
	printf("%s\n", buffer);
	close(fd);

	return 0;
}