/*
	dio_shark.h
	The main tracing source header file.
	
	This file declare core structures and interfaces
	in dio-shark, shark means tracing thread
*/

#include <pthread.h>
#include <stdbool.h>
/* defines */

#define BLKTRACESETUP _IOWR(0x12,115,struct user_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)

/* User Setup Structure */
struct user_setup {
	char name[32];
	__u16 act_mask;                 /* input */
	__u32 buf_size;                 /* input */
	__u32 buf_nr;                   /* input */
	__u64 start_lba;
	__u64 end_lba;
	__u32 pid;
};

struct devpath {
	char *path;
	char *buts_name;
	int fd, ncpus;
};

struct tracer {
	struct pollfd *pfds;
	pthread_t thread;
	int cpu;
	char debugFilePath[256];
	char outputFilePath[256];
	int dfp, ofp;

};

