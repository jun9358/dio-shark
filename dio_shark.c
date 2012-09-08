/*
   dio_shark.c
   the main project source file
   it contains 'main' function

   dio-shark is disk block tracing and analysis tool
   it will loosing sharks to each cpu
 */

#define _GNU_SOURCE		// it need to use CPU_ZERO(), CPU_SET()

#include <errno.h>		// errno, strerror()
#include <stdlib.h>		// malloc(), SIGINT, SIGHUP, SIGTERM, SIGPIPE, SIG_IGN
#include <signal.h>		// SIGINT, SIGHUP, SIGTERM, SIGPIPE, SIG_IGN
#include <stdio.h>		// stderr, fprintf(), printf()
#include <unistd.h>		// read()
#include <getopt.h>		// required_argument, arg_opts
#include <string.h>		// memset()
#include <fcntl.h>		// O_RDONLY, O_WRONLY, O_CREAT
#include <sys/ioctl.h>		// ioctl()
#include <stdbool.h>		// bool, true, false
#include <sys/poll.h>
#include <sched.h>		// CPU_ZERO(), CPU_SET(), shed_setaffinity()
#include <pthread.h>

#include "dio_shark.h"
//#include "dst/dio_list.h"

#define BUF_SIZE 	1024*8
#define BUF_NR		4

#define MAX_FILE_LENGTH 512

/* define macro and structure define */
#define BUTS_STAT_NONE		0
#define	BUTS_STAT_SETUPED	1
#define	BUTS_STAT_STARTED	2
#define	BUTS_STAT_STOPPED	3


static char outPath[MAX_FILE_LENGTH];
static char devPath[MAX_FILE_LENGTH];
static char devName[16];
/* global variables */
bool g_isdone = false;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_cond	= PTHREAD_COND_INITIALIZER;
pthread_barrier_t g_barrier;


/* function declaration */
struct list_head* create_list_head(void);

bool parse_args(int argc, char** argv);

void signalHandler(int idxSignal);
void set_signalHandler(void);
void put_signalHandler(void);

void wait_open_debugfs(void);
void* shark_body(void* param);
bool lock_shark_on_cpu(int idxCPU);

bool loose_sharks(struct list_head* shark_boss, int numCPU);
struct thread_shark* loose_shark(int idxCPU);
void* wait_comeback_shark(struct list_head* shark_boss);
void fasten_sharks(struct list_head* shark_boss);

int openfile_device(char *devpath);
int openfile_debugfs(int idxCPU);
int openfile_output(void);

void setup_buts(struct blk_user_trace_setup *pbuts);

/*
   main function
 */
int main(int argc, char** argv){
	int numCPU;
	int fdDevice = 0;
	struct blk_user_trace_setup buts;
	struct list_head *shark_boss = NULL;
	struct list_head *p;
	int buts_stat = BUTS_STAT_NONE;
	int ret;

	strcpy(outPath,"dioshark.output");

	DBGOUT("sysconf() entry \n");
	// get the number of cpus
	numCPU = sysconf(_SC_NPROCESSORS_ONLN);
	DBGOUT("set_signalHandler() entry \n");
	// set signal handler function
	set_signalHandler();

	// handle args
	if( !parse_args(argc, argv) ) {
		fprintf(stderr, "dio-shark argument error.\n");
		goto out;
	}

	DBGOUT("openfile_device() entry \n");
	// open device file	
	fdDevice = openfile_device(devPath);
	if(fdDevice < 0)
	{
		fprintf(stderr, "openfile_device() failed: %d/%s\n", errno, strerror(errno));
		goto out;
	}
	DBGOUT("setup_buts() entry \n");
	// setup blk_user_trace_setup
	setup_buts(&buts);
	DBGOUT("ioctl-BLKTRACESETUP entry \n");
	// device controller setup
	ret = ioctl(fdDevice, BLKTRACESETUP, &buts);
	if(ret < 0)
	{
		fprintf(stderr, "ioctl-BLKTRACESETUP failed: %d/%s\n", errno, strerror(errno));
		goto out;
	}
	buts_stat = BUTS_STAT_SETUPED;
	strcpy(devName,buts.name);
	DBGOUT("create_list_head() entry \n");
	// create list head for creating threads
	shark_boss = create_list_head();
	DBGOUT("loose_sharks() entry \n");
	// initialize barrier variable
	pthread_barrier_init(&g_barrier, NULL, numCPU + 1);

	// create threads
	ret = loose_sharks(shark_boss, numCPU);
	if(ret == (int)false)
	{
		fprintf(stderr, "loose_sharks() failed: %d/%s\n", errno, strerror(errno));
		goto out;
	}
	DBGOUT("wait_open_debugfs() entry \n");
	// wait until open debug file
	wait_open_debugfs();
	DBGOUT("ioctl-BLKTRACESTART entry \n");
	// device controller start
	ret = ioctl(fdDevice, BLKTRACESTART);
	if(ret < 0)
	{
		fprintf(stdout, "ioctl-BLKTRACESTART failed: %d/%s\n", errno, strerror(errno));
		goto out;
	}
	buts_stat = BUTS_STAT_STARTED;
	DBGOUT("wait_comeback_shark() entry \n");
	// wait until all thread terminate
	wait_comeback_shark(shark_boss);
out:

	DBGOUT("buts_stat = %d \n", buts_stat);
	// device controller stop
	if(buts_stat != BUTS_STAT_NONE)
	{
		ret = ioctl(fdDevice, BLKTRACESTOP);
		if(ret < 0)
		{
			fprintf(stdout, "ioctl-BLKTRACESTOP failed: %d/%s\n", errno, strerror(errno));
		}

		ret = ioctl(fdDevice, BLKTRACETEARDOWN);
		if(ret < 0)
		{
			fprintf(stdout, "ioctl-BLKTRACEDOWN failed: %d/%s\n", errno, strerror(errno));
		}
	}

	// fasten sharks that loosed
	if(!list_empty(shark_boss))
	{
		fasten_sharks(shark_boss);
	}

	// destroy list head
	if(shark_boss != NULL)
	{
		free(shark_boss);
	}

	// close device file
	if(fdDevice != 0)
	{
		close(fdDevice);
	}

	// put signal handler
	put_signalHandler();

	return 0;
}

struct list_head* create_list_head(void)
{
	struct list_head *head;

	head = (struct list_head*)malloc(sizeof(struct list_head));
	INIT_LIST_HEAD(head);

	return head;
}

/* start parse_args */
#define ARG_OPTS "d:o:"
static struct option arg_opts[] = {
	{
		.name = "device",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'd'
	},
	{
		.name = "outfile",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'o'
	}
};

char usage_detail[] = 	"\n"\
			 "  [ -d <device> ]\n"\
			 "  [ -o <outfile> ]\n"\
			 "\n"\
			 "\t-d : device which is traced\n"\
			 "\t-o : output file name\n";

bool parse_args(int argc, char** argv){
	char tok;
	int cnt = 0;

	while( (tok = getopt_long(argc, argv, ARG_OPTS, arg_opts, NULL)) >= 0 ){
		switch(tok){
			case 'd':
				strcpy(devPath,optarg);
				break;
			case 'o':
				strcpy(outPath,optarg);
				//set output file
				break;
			default:
				printf("USAGE : %s %s\n", argv[0], usage_detail);
				return false;
				break;
		};
		cnt++;
	}

	if(cnt == 0){
		fprintf(stderr, "dio-shark has no argument.\n");
		return false;
	}

	return true;
}
/* end parse_args */

void signalHandler(int idxSignal)
{
	g_isdone = true;
}
void set_signalHandler(void)
{
	signal(SIGINT, signalHandler);
	signal(SIGHUP, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGPIPE, SIG_IGN);
}
void put_signalHandler(void)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
}

/*
   Install Threads to get i/o data. 
 */
bool loose_sharks(struct list_head* shark_boss, int numCPU){
	struct thread_shark *tmpShark;
	int i;

	// install threads
	for(i=0 ; i<numCPU ; i++)
	{
		tmpShark = loose_shark(i);

		if(tmpShark == NULL)
			return false;
		list_add_tail(&(tmpShark->list), shark_boss);
	}

	return true;
}
struct thread_shark* loose_shark(int idxCPU)
{
	struct thread_shark *shark = NULL;
	int ret;

	shark = (struct thread_shark*)malloc(sizeof(struct thread_shark));
	shark->idxCPU = idxCPU;
	ret = pthread_create(&(shark->td), NULL, shark_body, shark);
	if(ret)
	{
		fprintf(stderr, "pthread_create(idxCPU:%d) failed:%d/%s\n", idxCPU, errno, strerror(errno));

		goto out;
	}

	return shark;

out:
	// release tshark memory
	if(shark != NULL)
		free(shark);

	return NULL;
}
void* wait_comeback_shark(struct list_head* shark_boss)
{
	void* tReturn;
	struct list_head* p;

	__list_for_each(p, shark_boss)
	{
		struct thread_shark *tmpShark;
		tmpShark = list_entry(p, struct thread_shark, list);
		pthread_join(tmpShark->td, &tReturn);
	}
}
void fasten_sharks(struct list_head* shark_boss)
{
	struct list_head* p, *q;

	list_for_each_safe(p, q, shark_boss)
	{
		struct thread_shark *tmpShark;
		tmpShark = list_entry(p, struct thread_shark, list);
		list_del(p);
		free(tmpShark);
	}
}
void wait_open_debugfs(void)
{
	pthread_barrier_wait(&g_barrier);
}
void* shark_body(void* param){
	struct blk_user_trace_setup buts;
	struct thread_shark *shark = param;
	struct pollfd fdpoll;
	int fdOutput;
	char buf[BUF_SIZE];
	int lenread;
	int ret;

	// lock this thread on one cpu
	ret = lock_shark_on_cpu(shark->idxCPU);
	if(!ret)
	{
		fprintf(stderr, "lock_shark_on_cpu() failed:%d/%s\n", errno, strerror(errno));
		goto out;
	}

	// open debug file
	fdpoll.fd = openfile_debugfs(shark->idxCPU);
	if(fdpoll.fd < 0)
	{
		fprintf(stderr, "openfile_debugfs() failed:%d/%s\n", errno, strerror(errno));
		goto out;
	}
	shark->isOpenDebugfs = true;

	// wake thread that wait opening debug file
	pthread_barrier_wait(&g_barrier);	

	// open output file
	fdOutput = openfile_output();
	if(fdOutput < 0)
	{
		fprintf(stderr, "openfile_output() failed:%d/%s\n", errno, strerror(errno));
		goto out;
	}

	// set poll data
	fdpoll.events	= POLLIN;
	fdpoll.revents	= 0;

	// get i/o data
	while(!g_isdone)
	{
		ret = poll(&fdpoll, 1, 500);
		if(ret < 0)
		{
			fprintf(stderr, "poll() failed:%d/%s\n", errno, strerror(errno));
			goto out;
		}
		else if(ret == 0)
		{
			continue;
		}

		if(fdpoll.revents & POLLIN)
		{
			memset(buf, 0, sizeof(buf));
			lenread = read(fdpoll.fd, buf, sizeof(buf));
			if(lenread < 0)
			{
				fprintf(stderr, "openfile_output() failed:%d/%s\n", errno, strerror(errno));
				goto out;
			}

			write(fdOutput, buf, lenread);
		}
	}

	//Write remain
	memset(buf, 0, sizeof(buf));
	lenread = read(fdpoll.fd, buf, sizeof(buf));
	if(lenread < 0)
	{
		fprintf(stderr, "openfile_output() failed:%d/%s\n", errno, strerror(errno));
		goto out;
	}

	write(fdOutput, buf, lenread);

out:
	// close output file
	if(!(fdOutput < 0))
		close(fdOutput);

	// close debugfs file
	if(!(fdpoll.fd < 0))
		close(fdpoll.fd);

	return NULL;
}
bool lock_shark_on_cpu(int idxCPU)
{
	cpu_set_t cpumask;
	int ret;

	// set cpu
	CPU_ZERO(&cpumask);
	CPU_SET(idxCPU, &cpumask);

	// lock cpu
	/*
	   If sched_setaffinity()'s pid(parameter1) is 0,
	   this pid point me.
	 */
	ret = sched_setaffinity(0, sizeof(cpumask), &cpumask);
	if(ret < 0)
		return false;
	return true;
}

int openfile_device(char *devpath){
	int fdDevice;

	fdDevice = open(devpath, O_RDONLY);
	if (fdDevice < 0)
		return -1;

	return fdDevice;
}
int openfile_debugfs(int idxCPU)
{
	int fdDebugfs;
	char buf[255];

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "/sys/kernel/debug/block/%s/trace%d", devName, idxCPU);

	fdDebugfs = open(buf, O_RDONLY);
	if (fdDebugfs < 0)
		return -1;

	return fdDebugfs;
}
int openfile_output(void)
{	int fdOutput;

	fdOutput = open(outPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fdOutput <0)
		return -1;

	return fdOutput;
}

void setup_buts(struct blk_user_trace_setup *pbuts)
{
	memset(pbuts, 0, sizeof(*pbuts));
	pbuts->buf_size	= BUF_SIZE;
	pbuts->buf_nr 	= BUF_NR;
	pbuts->act_mask = 0xffff;
}
