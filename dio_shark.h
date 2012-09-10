/*
	dio_shark.h
	The main tracing source header file.
	
	This file declare core structures and interfaces
	in dio-shark, shark means tracing thread
*/

#ifndef DIO_SHARK_H
#define DIO_SHARK_H

#include <pthread.h>	// pthread_t
#include <stdint.h>		// uint16_t
#include <stdbool.h>	// bool
#include "list.h"
#include "blktrace_api.h"

#ifdef DEBUG
# define DBGOUT(fmt, ...) printf("[%s] " fmt, __func__, ##__VA_ARGS__)
#else
# define DBGOUT(fmt, ...)
#endif

/* thread info */
struct thread_shark{
	struct list_head list;
	pthread_t td;
	bool isOpenDebugfs;
	int idxCPU;
};

#endif 
