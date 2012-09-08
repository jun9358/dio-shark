/*
	dio-shark.c
	the main project source file
	it contains 'main' function

	dio-shark is disk block tracing and analysis tool
	it will loosing sharks to each cpu
*/

#include <sched.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>

#include "dio-shark.h"

/* define macro and structure define */

/* global variables */
static struct devpath dp;
static struct tracer *tp;

/* thread */
static pthread_cond_t mt_cond    = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mt_mutext = PTHREAD_MUTEX_INITIALIZER;
static int thread_wait = 0;
static int thread_start = 0;

/* function declaration */
static void sig_handler(__attribute__((__unused__)) int sig);

bool parse_args(int argc, char** argv);

void stop_shark();

static int set_devpath(char *path);

static void start_tracer(int cpu);

static struct user_setup setup;

/* main function */
int main(int argc, char** argv){

	int i;
	
	//init settings
	dp.ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGPIPE, SIG_IGN);

	if( !parse_args(argc, argv) ){
		fprintf(stderr, "dio-shark argument error.\n");
		return 0;
	}
	//ioctl setup
	memset(&setup, 0, sizeof(setup));
	setup.buf_size = 512 * 1024;
	setup.buf_nr = 4;
	setup.act_mask = (__u16)~0U;

	if(ioctl(dp.fd, BLKTRACESETUP, &setup) == -1){
		fprintf(stderr, "%s ioctl failed: %d/%s\n", dp.path, errno, strerror(errno));
	}
	//start thread	

	//calloc	
	tp = (struct tracer *)malloc(sizeof(struct tracer)*dp.ncpus);
	memset(tp, 0, sizeof(*tp));
	
	for(i=0; i<dp.ncpus; i++) {
		tp[i].cpu = i;
		start_tracer(i);
	}
	//check end states
	while(thread_wait != dp.ncpus);

	if(ioctl(dp.fd,BLKTRACESTART) <0) {
		fprintf(stderr, "BLKTRACESTART %s failed :%d/%sn", dp.path, errno, strerror(errno));
	} else {
		thread_start = 1;
	}

	while(1);
}

static void *thread_main(void *arg){

	struct tracer *tp = arg;
	void *buf;
	buf = malloc(1024);
	memset(buf,0,1024);
	int read_size;
	snprintf(tp->debugFilePath, sizeof(tp->debugFilePath), "/sys/kernel/debug/block/%s/trace%d",setup.name,tp->cpu); 
	tp->dfp = open(tp->debugFilePath, O_RDONLY | O_NONBLOCK);
	
	if(tp->dfp<0) {
		fprintf(stderr, "thread %d fail: %d/%s\n", tp->cpu, errno, strerror(errno));
	}	

	snprintf(tp->outputFilePath, sizeof(tp->outputFilePath), "./shark_result.%s.%d",setup.name,tp->cpu);
	tp->ofp = open(tp->outputFilePath, O_WRONLY | O_CREAT);
	//에러체크 추가

	//mutex
	thread_wait++;

	while(thread_start!=1);

	while(1) {
		read_size = read(tp->dfp,buf,1024);
		if(read_size > 0) {
			write(tp->ofp,buf,read_size);
		}
		
	}	
}

static void start_tracer(int cpu) {
	pthread_create(&tp[cpu].thread, NULL, thread_main, &tp[cpu]);
}

void sig_handler(int sig){
	
	stop_shark();

}


void stop_shark() {
	int i;

	for(i=0;i<dp.ncpus;i++) {
		if(close(tp[i].dfp)<0) {
			fprintf(stderr, "thread %d close fail: %d/%s\n", i, errno, strerror(errno));
		}	
	}	

	ioctl(dp.fd,BLKTRACESTOP);	//STOP
	ioctl(dp.fd,BLKTRACETEARDOWN); //TEARDOWN
	
	exit(0);
	
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

	while( (tok = getopt_long(argc, argv, ARG_OPTS, arg_opts, NULL)) >= 0){
		switch(tok){
			case 'd':
				set_devpath(optarg);
				break;
			case 'o':
				printf("%s\n",optarg);
				//set output file
				break;
			default:
				printf("USAGE : %s %s\n", argv[0], usage_detail);
				return false;
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

static int set_devpath(char *path){
	dp.fd   = open(path, O_RDONLY | O_NONBLOCK);
	if(dp.fd < 0) {
		fprintf(stderr, "Invalid path %s specified: %d/%s\n", path, errno, strerror(errno));
	}
	dp.path = strdup(path);
		
}
