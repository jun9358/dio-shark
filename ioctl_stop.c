#include "dio_shark.h"
#include <sys/ioctl.h>
#include <fcntl.h>

int openfile_device(char *devpath){
        int fdDevice;

        fdDevice = open(devpath, O_RDONLY);
        printf("%d \n", fdDevice);
        if (fdDevice < 0)
                return -1;

        return fdDevice;
}

int main(void)
{
	int fdDevice;

	fdDevice = openfile_device("/dev/sda");

	ioctl(fdDevice, BLKTRACESTOP);
	ioctl(fdDevice, BLKTRACETEARDOWN);

	return 0;
}
