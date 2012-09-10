/*
   The parser for binary result of dio-shark

	
	This source is free on GNU General Public License.
*/

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dio_shark.h"
#include "list.h"
#include "rbtree.h"
#include "blktrace_api.h"

/*--------------	struct and defines	------------------*/
#define SECONDS(x)              ((unsigned long long)(x) / 1000000000)
#define NANO_SECONDS(x)         ((unsigned long long)(x) % 1000000000)
#define DOUBLE_TO_NANO_ULL(d)   ((unsigned long long)((d) * 1000000000))

#define BLK_ACTION_STRING		"QMFGSRDCPUTIXBAad"
#define GET_ACTION_CHAR(x)      (0<(x&0xffff) && (x&0xffff)<sizeof(BLK_ACTION_STRING))?BLK_ACTION_STRING[(x & 0xffff) - 1]:'?'

#define BE_TO_LE16(word) \
	(((word)>>8 & 0x00FF) | ((word)<<8 & 0xFF00))

#define BE_TO_LE32(dword) \
	(((dword)>>24 & 0x000000FF) | ((dword)<<24 & 0xFF000000) |\
	((dword)>>8  & 0x0000FF00) | ((dword)<<8  & 0x00FF0000))

#define BE_TO_LE64(qword) \
	(((qword)>>56 & 0x00000000000000FF) | ((qword)<<56 & 0xFF00000000000000) |\
	((qword)>>40 & 0x000000000000FF00) | ((qword)<<40 & 0x00FF000000000000) |\
	((qword)>>24 & 0x0000000000FF0000) | ((qword)<<24 & 0x0000FF0000000000) |\
	((qword)>>8  & 0x00000000FF000000) | ((qword)<<8  & 0x000000FF00000000))

#define BE_TO_LE_BIT(bit) \
	(bit).magic 	= BE_TO_LE32((bit).magic);\
	(bit).sequence 	= BE_TO_LE32((bit).sequence);\
	(bit).time	= BE_TO_LE64((bit).time);\
	(bit).sector	= BE_TO_LE64((bit).sector);\
	(bit).bytes	= BE_TO_LE32((bit).bytes);\
	(bit).action	= BE_TO_LE32((bit).action);\
	(bit).pid	= BE_TO_LE32((bit).pid);\
	(bit).device	= BE_TO_LE32((bit).device);\
	(bit).cpu	= BE_TO_LE32((bit).cpu);\
	(bit).error	= BE_TO_LE16((bit).error);\
	(bit).pdu_len	= BE_TO_LE16((bit).pdu_len)


// dio_rbentity used for handling nuggets as sector order
struct dio_rbentity{
	struct rb_node rblink;		//red black tree link
	struct list_head nghead;	//head of nugget list
	uint64_t sector;
};

// dio_nugget is a treated data of bit
// it will be linked at dio_rbentity 's nghead
#define MAX_ELEMENT_SIZE 50
#define NG_ACTIVE	1
#define NG_BACKMERGE	2
#define NG_FRONTMERGE	3
#define NG_COMPLETE	4
struct dio_nugget{
	struct list_head nglink;	//link of dio_nugget datatype

	//real nugget data
	int elemidx;	//element index. (elemidx-1) is count of nugget states
	int category;
	char states[MAX_ELEMENT_SIZE];	//action
	uint64_t times[MAX_ELEMENT_SIZE];	//states[elemidx] is occured at times[elemidx]
	int size;	//size of nugget
	uint64_t sector;	//sector number of bit who was requested. is it really need?
	uint32_t pid;
	struct dio_nugget* mlink;	//if it was merged, than mlink points the other nugget
	int ngflag;
	int idxCPU;
};

// list node of blk_io_trace
// it just maintain the time ordered bits
struct bit_entity{
	struct list_head link;
	
	struct blk_io_trace bit;
};

struct data_time
{
	unsigned int total_time;
	unsigned int count;
	unsigned int average_time;

	unsigned int min_time;
	unsigned int max_time;
};

struct dio_nugget_path
{
	struct list_head link;

	int elemidx;
	char states[MAX_ELEMENT_SIZE];

	struct data_time data_time_read;
	struct data_time data_time_write;

	struct data_time* data_time_interval_read;
	struct data_time* data_time_interval_write;
};

struct dio_cpu
{
	int r_cnt;
	int w_cnt;
	int x_cnt;
};

// statistic initialize function.
typedef void(*statistic_init_func)(void);

// statistic traveling function. 
// rb traveling function will be given the each nugget as a parameter
typedef void(*statistic_travel_func)(struct dio_nugget*);

// statistic iterating function.
// list iterating function will be given the each bit as a parameter
typedef void(*statistic_itr_func)(struct blk_io_trace*);

// data process function.
typedef void(*statistic_process_func)(int);

#define MAX_STATISTIC_FUNCTION 10

/*--------------	function interfaces	-----------------------*/
/* function for option handling */
bool parse_args(int argc, char** argv);

/* function for bit list */
// insert bit_entity data into rbiten_head order by time
static void insert_proper_pos(struct bit_entity* pbiten);

/* function for rbentity */
//initialize dio_rbentity
static void init_rbentity(struct dio_rbentity* prben);
static struct dio_rbentity* rb_search_entity(uint64_t sector);
static struct dio_rbentity* rb_search_end(uint64_t sec_t);
static struct dio_rbentity* __rb_insert_entity(struct dio_rbentity* prben);
static struct dio_rbentity* rb_insert_entity(struct dio_rbentity* prben);

/* function for nugget */
static void init_nugget(struct dio_nugget* pdng);
static void copy_nugget(struct dio_nugget* destng, struct dio_nugget* srcng);
static struct dio_nugget* FRONT_NUGGET(struct list_head* png_head);

// it return a valid nugget point even if inserted 'sector' doesn't existed in rbtree
// if NULL value is returned, reason is a problem of inserting the new rbentity 
// or memory allocating the new nugget 
static struct dio_nugget* get_nugget_at(uint64_t sector);

// create active nugget on rbtree
// if there isn't rbentity of sector number 'sector', than it create rbentity automatically
// and return the pointer of created nugget
static struct dio_nugget* create_nugget_at(uint64_t sector);

// delete active nugget from rbtree
static void delete_nugget_at(uint64_t sector);

static void extract_nugget(struct blk_io_trace* pbit, struct dio_nugget* pdngbuf);
static void handle_action(uint32_t act, struct dio_nugget* pdng);

// add the statistic callback functions
static void add_nugget_stat_func(statistic_init_func stat_init_fn, 
					statistic_travel_func stat_trv_fn,
					statistic_process_func stat_proc_fn);
static void add_bit_stat_func(statistic_init_func stat_init_fn,
					statistic_itr_func stat_itr_fn,
					statistic_process_func stat_proc_fn);

// traveling the rb tree with execution the added statistic functions
static void statistic_rb_traveling();

// statistic for each list entity
static void statistic_list_for_each();

// print functions
void print_data_time_statistic(FILE* stream, struct data_time* pdata_time);

void print_time();
void print_sector();

// disk I/O type statistic (just count)
void init_type_statistic();
void itr_type_statistic(struct blk_io_trace* pbit);
void process_type_statistic(int bit_cnt);

// path statistic functions
int instr(const char* str1, const char* str2);
struct dio_nugget_path* find_nugget_path(struct list_head* nugget_path_head, char* states);
void init_path_statistic(void);
void travel_path_statistic(struct dio_nugget* pdng);
void process_path_statistic(int ng_cnt);

// cpu statistic functions
void create_diocpu(void);
void init_cpu_statistic(void);
void itr_cpu_statistic(struct blk_io_trace* pbit);
void process_cpu_statistic(int bit_cnt);

// pid statistic functions
struct pid_stat_data{
	struct rb_node link;

	uint32_t pid;
        struct data_time data_time_read;
        struct data_time data_time_write;
};
static struct rb_root psd_root = RB_ROOT;	//pid stat data root

static struct pid_stat_data* rb_search_psd(uint32_t pid);
static struct pid_stat_data* __rb_insert_psd(struct pid_stat_data* newpsd);
static struct pid_stat_data* rb_insert_psd(struct pid_stat_data* newpsd);
static void __clear_pid_stat(struct rb_node* p);
void init_pid_statistic();
void travel_pid_statistic(struct dio_nugget* pdng);
void process_pid_statistic(int ng_cnt);

/*--------------	global variables	-----------------------*/
#define MAX_FILEPATH_LEN 255
#define PRINT_TYPE_TIME 0
#define PRINT_TYPE_SECTOR 1

static char respath[MAX_FILEPATH_LEN];	//result file path
static int print_type;
static FILE *output;
static uint64_t time_start;		/* in nanoseconds */
static uint64_t time_end;
static uint64_t sector_start;
static uint64_t sector_end;
static uint64_t filter_pid;

static struct rb_root rben_root;	//root of rbentity tree
static struct list_head biten_head;

static statistic_init_func stat_init_fns[MAX_STATISTIC_FUNCTION];
static statistic_travel_func stat_trv_fns[MAX_STATISTIC_FUNCTION];
static statistic_itr_func stat_itr_fns[MAX_STATISTIC_FUNCTION];
static statistic_process_func stat_proc_fns[MAX_STATISTIC_FUNCTION];
static int stat_fn_cnt = 0;		//statistic callback functions iterated on tree
static int stat_fn_list_cnt = 0;	//statistic callback functions iterated on list.
					//callback function for list is filled from the 
					//last index of callback table

#define ARG_OPTS "i:o:p:T:S:P:s"
static struct option arg_opts[] = {
	{	
		.name = "resfile",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'i',
	},	
	{
		.name = "outfile",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'o'
	}, 
	{
		.name = "print",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'p'
	},
	{
		.name = "time",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'T'
	},
	{
		.name = "sector",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'S'
	},
	{
		.name = "pid",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'P'
	},
	{
		.name = "statistic",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 's'
	}
};

/*--------------	function implementations	---------------*/
int main(int argc, char** argv){
	INIT_LIST_HEAD(&biten_head);
	rben_root = RB_ROOT;

	print_type = PRINT_TYPE_TIME;
	time_start = 0;
	time_end = (uint64_t)(-1);
	sector_start = 0;
	sector_end = (uint64_t)(-1);
	filter_pid = (uint64_t)(-1);


	int ifd = -1;
	int rdsz = 0;
	char pdubuf[256];

	strncpy(respath, "dioshark.output", MAX_FILEPATH_LEN);

	parse_args(argc, argv);
	ifd = open(respath, O_RDONLY);
	if( ifd < 0 ){
		perror("failed to open result file");
		goto err;
	}
	
	struct bit_entity* pbiten = NULL;
	struct dio_nugget* pdng = NULL;

	int i = 0;
	while(1){
		if( pbiten == NULL ){
			pbiten = (struct bit_entity*)malloc(sizeof(struct bit_entity));
			if( pbiten == NULL ){
				perror("failed to allocate memory");
				goto err;
			}
		}

		rdsz = read(ifd, &(pbiten->bit), sizeof(struct blk_io_trace));
		if( rdsz < 0 ){
			perror("failed to read");
			goto err;
		}
		else if( rdsz == 0 ){
			break;
		}

		//BE_TO_LE_BIT(pbiten->bit);

		//DBGOUT(">pdu_len : %d\n", pbiten->bit.pdu_len);
		if( pbiten->bit.pdu_len > 0 ){
			//rdsz = read(ifd, pdubuf, pbiten->bit.pdu_len);
			//pdubuf[rdsz] = '\0';
			//DBGOUT(">pdu data : %s\n", pdubuf);
			lseek(ifd, pbiten->bit.pdu_len, SEEK_CUR);
		}
		
		//filter
		if( (time_start > pbiten->bit.time || time_end < pbiten->bit.time) ||
			(sector_start > pbiten->bit.sector || sector_end < pbiten->bit.sector) )
			continue;
		if( filter_pid !=(uint64_t)(-1) && filter_pid != pbiten->bit.pid )
			continue;

		if( (pbiten->bit.action >> BLK_TC_SHIFT) == BLK_TC_NOTIFY )
			continue;
			
		//insert into list order by time
		insert_proper_pos(pbiten);

		pbiten = NULL;
	}

	//build up the rbtree order by number of sector
	struct bit_entity* p = NULL;
	uint64_t recentsect = 0;
	list_for_each_entry(p, &biten_head, link){
#if 0
		if( p->bit.sector != 0 )
			recentsect = p->bit.sector;
#endif
		
		pdng = get_nugget_at(p->bit.sector);

		if( pdng == NULL ){
			DBGOUT(">failed to get nugget at sector %llu\n", p->bit.sector);
			goto err;
		}
		extract_nugget(&p->bit, pdng);
	}



	if(output==NULL) {
		output = stdout;
	}

	if(print_type == PRINT_TYPE_TIME) {
		add_bit_stat_func(NULL, NULL, print_time);
	} else if(print_type == PRINT_TYPE_SECTOR) {
		add_nugget_stat_func(NULL, NULL, print_sector);
	}

	//statistic_rb_traveling();
	//statistic_list_for_each();

	//clean all list entities
	if(output!=stdout){
		fclose(output);
	}

	return 0;
err:
	if( ifd < 0 )
		close(ifd);
	if( pbiten != NULL )
		free(pbiten);
	return 0;
}

bool parse_args(int argc, char** argv){
	char tok;
	char *p;
	
	while( (tok = getopt_long(argc, argv, ARG_OPTS, arg_opts, NULL)) >= 0){
	switch(tok){
	case 'i':
		memset(respath,0,sizeof(char)*MAX_FILEPATH_LEN);
		strcpy(respath,optarg);
		break;
	case 'p':
		if(!strcmp("sector",optarg)) {
			print_type = PRINT_TYPE_SECTOR;
		} else if(!strcmp("time",optarg)) {
			print_type = PRINT_TYPE_TIME;
		} else {
			printf("Print Type Error\n");
			exit(1);
		}
                break;
	case 'o':
		output = fopen(optarg,"w");
		if(output==NULL) {
			printf("Output File Open Error\n");
			exit(1);
		}
                break;
	case 'T':
		p = strtok(optarg,",");
		time_start = (uint64_t)atoi(p) * 1000000000;
		p = strtok(NULL,",");
		time_end = (uint64_t)atoi(p) * 1000000000;
		break;
	case 'S':
		p = strtok(optarg,",");
		sector_start = (uint64_t)atoll(p);
		p = strtok(NULL,",");
		sector_end = (uint64_t)atoll(p);
		break;
	case 'P':
		filter_pid = (uint64_t)atoi(optarg);
		break;
	case 's':
		//path, pid, cpu	
		break;
        };
    }
    return true;
}

void insert_proper_pos(struct bit_entity* pbiten){
	struct list_head* p = NULL;
	struct bit_entity* _pbiten = NULL;

	//list foreach back
	for(p = biten_head.prev; p != &(biten_head); p = p->prev){
		_pbiten = list_entry(p, struct bit_entity, link);
		if( _pbiten->bit.time <= pbiten->bit.time ){
			list_add(&(pbiten->link), p);
			return;
		}
	}
	list_add(&(pbiten->link), &(biten_head));
}

static void init_rbentity(struct dio_rbentity* prben){
	memset(prben, 0, sizeof(struct dio_rbentity));
	INIT_LIST_HEAD(&prben->nghead);
	prben->sector = 0;
}

static struct dio_rbentity* rb_search_entity(uint64_t sector){
	struct rb_node* p = rben_root.rb_node;
	struct dio_rbentity* prben = NULL;

	while(p){
		prben = rb_entry(p, struct dio_rbentity, rblink);
		if( sector < prben->sector )
			p = prben->rblink.rb_left;
		else if( sector > prben->sector )
			p = prben->rblink.rb_right;
		else
			return prben;
	}
	return NULL;
}

struct dio_rbentity* rb_search_end(uint64_t sec_t){
	struct rb_node* p = rben_root.rb_node;
	struct dio_rbentity* prben = NULL;
	struct dio_nugget* actng = NULL;
	uint64_t calcsect = 0;

	while(p){
		prben = rb_entry(p, struct dio_rbentity, rblink);
		actng = FRONT_NUGGET(&prben->nghead);
		if( prben->sector != actng->sector ){
			DBGOUT("prben->sector != actng->sector\n");
			return NULL;
		}
		calcsect = actng->sector + actng->size/512;

		if( sec_t < calcsect )
			p = prben->rblink.rb_left;
		else if( sec_t > calcsect )
			p = prben->rblink.rb_right;
		else
			return prben;
	}
	return NULL;
}

struct dio_nugget* FRONT_NUGGET(struct list_head* png_head){
	if( list_empty(png_head) )
		DBGOUT(">>>>>>>>>>>>>>>> list empty\n");

	return list_entry(png_head->next, struct dio_nugget, nglink);
}

static struct dio_rbentity* __rb_insert_entity(struct dio_rbentity* prben){
	struct rb_node** p = &rben_root.rb_node;
	struct rb_node* parent = NULL;
	struct dio_rbentity* prbenbuf = NULL;

	while(*p){
		parent = *p;
		prbenbuf = rb_entry(parent, struct dio_rbentity, rblink);

		if( prben->sector < prbenbuf->sector )
			p = &(*p)->rb_left;
		else if( prben->sector > prbenbuf->sector )
			p = &(*p)->rb_right;
		else
			return prbenbuf;	//there already exists
	}

	rb_link_node(&(prben->rblink), parent, p);
	return NULL;	//success
}

static struct dio_rbentity* rb_insert_entity(struct dio_rbentity* prben){
	struct dio_rbentity* rbenret = NULL;
	if( (rbenret = __rb_insert_entity(prben)) )
		return rbenret;	//there already exists

	rb_insert_color(&(prben->rblink), &(rben_root));
	return NULL;	//insert successfully
}

void init_nugget(struct dio_nugget* pdng){
	memset(pdng, 0, sizeof(struct dio_nugget));
	//pdng->elemidx = 0;
}

void copy_nugget(struct dio_nugget* destng, struct dio_nugget* srcng){
	memcpy(destng, srcng, sizeof(struct dio_nugget));
}

struct dio_nugget* get_nugget_at(uint64_t sector){
	struct dio_nugget* pdng = NULL;
	struct dio_rbentity* prben = NULL;

	prben = rb_search_entity(sector);
	if( prben == NULL ){
		prben = (struct dio_rbentity*)malloc(sizeof(struct dio_rbentity));
		if( prben == NULL){
			DBGOUT("failed to get memory\n");
			return NULL;
		}
		init_rbentity(prben);
		prben->sector = sector;
		if( rb_insert_entity(prben) != NULL ){
			free(prben);
			DBGOUT(">failed to insert rbentity into rbtree\n");
			return NULL;
		}
	}

	//return the first item of nugget list
	if( !list_empty(&prben->nghead) ){
		pdng = FRONT_NUGGET(&prben->nghead);
		if( pdng->ngflag == NG_ACTIVE ){
			return pdng;
		}
	}

	//else if list is empty or first item is inactive
	pdng = NULL;
	pdng = (struct dio_nugget*)malloc(sizeof(struct dio_nugget));
	if( pdng == NULL ){
		perror("failed to allocate nugget memory");
		return NULL;
	}

	init_nugget(pdng);
	pdng->sector = sector;
	pdng->ngflag = NG_ACTIVE;
	list_add(&pdng->nglink, &prben->nghead);

	return pdng;
}

struct dio_nugget* create_nugget_at(uint64_t sector){
	struct dio_rbentity* rben = rb_search_entity(sector);
	if( rben == NULL ){
		rben = (struct dio_rbentity*)malloc(sizeof(struct dio_rbentity));
		if( rben == NULL ){
			perror("failed to allocate rbentity memory");
			return NULL;
		}
		init_rbentity(rben);
		rben->sector = sector;

		rb_insert_entity(rben);
	}

	struct dio_nugget* newng = NULL;
	newng = (struct dio_nugget*)malloc(sizeof(struct dio_nugget));
	if( newng == NULL ){
		perror("failed to allocate nugget memory");
		return NULL;
	}
	init_nugget(newng);
	newng->sector = sector;
	newng->ngflag = NG_ACTIVE;
	list_add(&newng->nglink, &rben->nghead);

	return newng;
}

void delete_nugget_at(uint64_t sector){
	struct dio_rbentity* prben = rb_search_entity(sector);
	if( prben == NULL )
		return;
	
	if( list_empty(&prben->nghead) )
		return;

	struct dio_nugget* del = FRONT_NUGGET(&prben->nghead);
	list_del(prben->nghead.next);
	free(del);
}

void extract_nugget(struct blk_io_trace* pbit, struct dio_nugget* pdngbuf){
	pdngbuf->times[pdngbuf->elemidx] = pbit->time;
	if( pdngbuf->elemidx == 0 ){
		pdngbuf->size = pbit->bytes;
		pdngbuf->pid = pbit->pid;
		pdngbuf->category = pbit->action >> BLK_TC_SHIFT;
	}

	handle_action(pbit->action, pdngbuf);
	pdngbuf->category = pbit->action >> BLK_TC_SHIFT;
	if(pbit->cpu < 128)
	{
		pdngbuf->idxCPU = pbit->cpu;
	}
	pdngbuf->elemidx++;
}

void handle_action(uint32_t act, struct dio_nugget* pdng){
	struct dio_nugget* ptmpng = NULL;
	struct dio_nugget* newng = NULL;
	struct dio_rbentity* prben = NULL;

	char actc = GET_ACTION_CHAR(act);
	pdng->states[pdng->elemidx] = actc;

	switch(act){
	case 'M':
		//back merged
		prben = rb_search_end(pdng->sector);
		if( prben == NULL ){
			DBGOUT("Failed to search nugget when back merging\n");
			return;
		}
		ptmpng = FRONT_NUGGET(&prben->nghead);
		
		pdng->ngflag = NG_BACKMERGE;
		pdng->mlink = ptmpng;
		ptmpng->size += pdng->size;
		break;

	case 'F':
		//front merged
		newng = create_nugget_at(pdng->sector);
		if( newng == NULL ){
			DBGOUT("Failed to create nugget\n");
			return;
		}
		prben = rb_search_entity(pdng->sector + pdng->size);
		if( prben == NULL ){
			DBGOUT("Failed to search nugget when front merging\n");
			return;
		}
		ptmpng = FRONT_NUGGET(&prben->nghead);
		copy_nugget(newng, ptmpng);

		pdng->ngflag = NG_FRONTMERGE;
		pdng->mlink = ptmpng;
		delete_nugget_at(pdng->sector + pdng->size);
		break;
	case 'C':
		pdng->ngflag = NG_COMPLETE;
		break;
	};
}

void add_nugget_stat_func(statistic_init_func stat_init_fn, 
				statistic_travel_func stat_trv_fn,
				statistic_process_func stat_proc_fn){
	if( stat_fn_cnt +1 >= MAX_STATISTIC_FUNCTION )
		return;
	
	stat_init_fns[stat_fn_cnt] = stat_init_fn;
	stat_trv_fns[stat_fn_cnt] = stat_trv_fn;
	stat_proc_fns[stat_fn_cnt] = stat_proc_fn;
	stat_fn_cnt++;
}

void add_bit_stat_func(statistic_init_func stat_init_fn,
				statistic_itr_func stat_itr_fn,
				statistic_process_func stat_proc_fn){
	if( stat_fn_list_cnt >= MAX_STATISTIC_FUNCTION - stat_fn_cnt )
		return;
	
	stat_init_fns[MAX_STATISTIC_FUNCTION - stat_fn_list_cnt - 1] = stat_init_fn;
	stat_itr_fns[MAX_STATISTIC_FUNCTION - stat_fn_list_cnt - 1] = stat_itr_fn;
	stat_proc_fns[MAX_STATISTIC_FUNCTION - stat_fn_list_cnt - 1] = stat_proc_fn;
	stat_fn_list_cnt ++;
}

void statistic_rb_traveling(){
	struct rb_node* node;
	int i=0, cnt=0;

	//init all statistic functions
	for(i=0; i<stat_fn_cnt; i++){
		if( stat_init_fns[i] != NULL )
			stat_init_fns[i]();
	}
	
	node = rb_first(&rben_root);
	do{
		struct dio_rbentity* prben = NULL;
		prben = rb_entry(node, struct dio_rbentity, rblink);

		struct dio_nugget* pdng = NULL;
		list_for_each_entry(pdng, &prben->nghead, nglink){
			//traveling
			for(i=0; i<stat_fn_cnt; i++){
				if( stat_trv_fns[i] != NULL )
					stat_trv_fns[i](pdng);	
			}
			cnt++;
		}
	}while((node = rb_next(node)) != NULL);

	//process data
	for(i=0; i<stat_fn_cnt; i++){
		if( stat_proc_fns[i] != NULL )
			stat_proc_fns[i](cnt);
	}

}

void statistic_list_for_each(){
	struct bit_entity* pos;
	int i=0, cnt=0;
	int itrcnt = MAX_STATISTIC_FUNCTION - stat_fn_list_cnt;

	//init all statistic functions
	for(i=MAX_STATISTIC_FUNCTION-1; i >= itrcnt; i--){
		if( stat_init_fns[i] != NULL )
			stat_init_fns[i]();
	}
	
	list_for_each_entry(pos, &biten_head, link){
		//foreach data
		for(i=MAX_STATISTIC_FUNCTION-1; i >= itrcnt; i--){
			if( stat_itr_fns[i] != NULL )
				stat_itr_fns[i](&pos->bit);
		}
	}

	//process data
	for(i=MAX_STATISTIC_FUNCTION-1; i >= itrcnt; i--){
		if( stat_proc_fns[i] != NULL )
			stat_proc_fns[i](cnt);
	}

}

//------------------- printing -------------------------------------//
void print_time() {
	struct bit_entity* p = NULL;

	list_for_each_entry(p, &biten_head, link) {

		fprintf(output,"%5d.%09lu\t", (int)SECONDS(p->bit.time), (unsigned long)NANO_SECONDS(p->bit.time));
		fprintf(output,"%llu\t",p->bit.sector);
		fprintf(output,"%u\t",p->bit.pid);
		fprintf(output,"%u\n",p->bit.bytes/8);
	}
}

void print_sector() {

	struct rb_node *node;
	node = rb_first(&rben_root);
	while((node = rb_next(node)) != NULL) {
		struct list_head* nugget_head;
		struct dio_rbentity* prbentity;

		prbentity = rb_entry(node, struct dio_rbentity, rblink);

		struct dio_nugget* pdng;
		uint64_t tmpt = 0;

		list_for_each_entry(pdng, &(prbentity->nghead), nglink) {
			tmpt = pdng->times[pdng->elemidx-1] - pdng->times[0];
			fprintf(output,"%"PRIu64"\t",pdng->sector);
			fprintf(output,"%5d.%09lu\t",(int)SECONDS(tmpt), (unsigned long)NANO_SECONDS(tmpt));
			fprintf(output,"%u\t", pdng->pid);
			fprintf(output,"%d\n", pdng->size);
		}
	}
}

//------------------- i/o type statistics -------------------------------//
static int r_cnt,w_cnt,x_cnt;

void init_type_statistic(){
	r_cnt = w_cnt = x_cnt = 0;
}

void itr_type_statistic(struct blk_io_trace* pbit){
	uint32_t category = pbit->action >> BLK_TC_SHIFT;

	if( category & BLK_TC_READ )
		r_cnt++;
	else if( category & BLK_TC_WRITE )
		w_cnt++;
	else
		x_cnt++;
}

void process_type_statistic(int bit_cnt){
	int tot;
	fprintf(output, "%7s %10s %13s\n", "TYPE","COUNT","PERCENTAGE");
	
	fprintf(output, "%7s %10d %13lf\n", "R",r_cnt, r_cnt/(double)bit_cnt*100);
	fprintf(output, "%7s %10d %13lf\n", "W",w_cnt,w_cnt/(double)bit_cnt*100);
	fprintf(output, "%7s %10d %13lf\n", "Unknown",x_cnt, x_cnt/(double)bit_cnt*100);

	tot = r_cnt + w_cnt + x_cnt;
	fprintf(output, "%7s %10d %13lf\n", "Total :",tot, tot/(double)bit_cnt*100);
}

//------------------- path statistics ------------------------------//
struct list_head nugget_path_head;
struct dio_nugget_path* pnugget_path;

int instr(const char* str1, const char* str2)
{
        int i, j;

        i=0;
        while(str1[i] != '\0')
        {
                j=0;
                while(str2[j] != '\0')
                {
                        if(str1[i+j] != str2[j])
                        {
                                break;
                        }
                        j++;
                }
                if(str2[j] == '\0')
                {
                        return i+1;
                }
                i++;
        }

        return 0;
}

struct dio_nugget_path* find_nugget_path(struct list_head* nugget_path_head, char* states)
{
	struct dio_nugget_path* pdngpath;

	list_for_each_entry(pdngpath, nugget_path_head, link)
	{
		if(strcmp(pdngpath->states, states) == 0)
		{
			return pdngpath;
		}
	}

	return NULL;
}

void init_path_statistic(void)
{
	INIT_LIST_HEAD(&nugget_path_head);
}

void travel_path_statistic(struct dio_nugget* pdng)
{
	char* 			pstates;
	uint64_t*		ptimes;
	int*			pelemidx;
	int			i;
	int			nugget_time;
	int			nugget_time_interval;
	struct data_time*	pdata_time;
	struct data_time*	pdata_time_interval;
	
	pnugget_path = find_nugget_path(&nugget_path_head, pdng->states);
	if(pnugget_path == NULL)	// if not exist
	{
		pnugget_path = (struct dio_nugget_path*)malloc(sizeof(struct dio_nugget_path));
		memset(pnugget_path, 0, sizeof(struct dio_nugget_path));

		pnugget_path->data_time_interval_read = (struct data_time*)malloc(sizeof(struct data_time) * pdng->elemidx);
		pnugget_path->data_time_interval_write = (struct data_time*)malloc(sizeof(struct data_time) * pdng->elemidx);

		// Init pnugget_path's members
		pnugget_path->elemidx = pdng->elemidx;
		pnugget_path->data_time_read.min_time = -1;
		pnugget_path->data_time_write.min_time = -1;
		for(i=0 ; i<pnugget_path->elemidx ; i++)
		{
			pnugget_path->data_time_interval_read[i].min_time = -1;
			pnugget_path->data_time_interval_write[i].min_time = -1;
		}
		strncpy(pnugget_path->states, pdng->states, MAX_ELEMENT_SIZE);

		// Add list
		list_add(&(pnugget_path->link), &nugget_path_head);
	}

	// Add read/write count to distribute those.
	if(pdng->category & BLK_TC_READ)
	{
		pdata_time = &pnugget_path->data_time_read;
		pdata_time_interval = pnugget_path->data_time_interval_read;
	}
	if(pdng->category & BLK_TC_WRITE)
	{
		pdata_time = &pnugget_path->data_time_write;
		pdata_time_interval = pnugget_path->data_time_interval_write;
	}

	// Set data on pnugget_path.
	nugget_time = pdng->times[pnugget_path->elemidx-1] - pdng->times[0];
	pdata_time->count++;
	pdata_time->total_time += nugget_time;
	if(pdata_time->max_time < nugget_time)
	{
		pdata_time->max_time = nugget_time;
	}
	if(pdata_time->min_time > nugget_time)
	{
		pdata_time->min_time = nugget_time;
	}

	// Set data on pnugget_path->data_time_interval
	for(i=0 ; i<pnugget_path->elemidx ; i++)
	{
		nugget_time_interval = pdng->times[i+1] - pdng->times[i];
		pdata_time_interval[i].count++;
		pdata_time_interval[i].total_time += nugget_time_interval;
		if(pdata_time_interval[i].max_time < nugget_time)
		{
			pdata_time_interval[i].max_time = nugget_time;
		}
		if(pdata_time_interval[i].min_time > nugget_time)
		{
			pdata_time_interval[i].min_time = nugget_time;
		}
	}
}


void process_path_statistic(int ng_cnt)
{
	int i;

	fprintf(output,"%20s %6s %6s %12s %12s %12s \n", "Path", "Type", "No", "AverageTime", "MaxTime", "MinTime");

	list_for_each_entry(pnugget_path, &nugget_path_head, link)
	{
		// Calculate average time(path)
		if(pnugget_path->data_time_read.count != 0)
		{
			pnugget_path->data_time_read.average_time = pnugget_path->data_time_read.total_time / pnugget_path->data_time_read.count;
		}
		if(pnugget_path->data_time_write.count != 0)
		{
			pnugget_path->data_time_write.average_time = pnugget_path->data_time_write.total_time / pnugget_path->data_time_write.count;
		}

		// if min_time is -1 that initializing value for calculating min_time, change that to 0.
		if(pnugget_path->data_time_read.min_time == -1)
		{
			pnugget_path->data_time_read.min_time = 0;
		}
		if(pnugget_path->data_time_write.min_time == -1)
		{
			pnugget_path->data_time_write.min_time = 0;
		}

		// Calculate average time(path interval)
		for(i=0 ; i<pnugget_path->elemidx ; i++)
		{
			if(pnugget_path->data_time_interval_read[i].count != 0)
			{
				pnugget_path->data_time_interval_read[i].average_time = pnugget_path->data_time_interval_read[i].total_time / pnugget_path->data_time_interval_read[i].count;
			}
			if(pnugget_path->data_time_interval_write[i].count != 0)
			{
				pnugget_path->data_time_interval_write[i].average_time = pnugget_path->data_time_interval_write[i].total_time / pnugget_path->data_time_interval_write[i].count;
			}
	
			// if min_time is -1 that initializing value for calculating min_time, change that to 0.
			if(pnugget_path->data_time_interval_read[i].min_time == -1)
			{
				pnugget_path->data_time_interval_read[i].min_time = 0;
			}
			if(pnugget_path->data_time_interval_write[i].min_time == -1)
			{
				pnugget_path->data_time_interval_write[i].min_time = 0;
			}
		}

		//printing
		if(instr(pnugget_path->states, "P") || instr(pnugget_path->states, "U") || instr(pnugget_path->states, "?"))
		{
			continue;
		}
		fprintf(output, "%20s %6s ", pnugget_path->states, "Read");
		print_data_time_statistic(output, &pnugget_path->data_time_read);
		fprintf(output, "\n");

		fprintf(output, "%20s %6s ", " ", "Write");
		print_data_time_statistic(output, &pnugget_path->data_time_write);
		fprintf(output, "\n");

		for(i=0 ; i<pnugget_path->elemidx-1 ; i++)
		{
			fprintf(output, "%18s%.2s %6s ", " ", &pnugget_path->states[i], "Read");
			print_data_time_statistic(output, &pnugget_path->data_time_interval_read[i]);
			if(pnugget_path->data_time_read.average_time != 0)
			{
				fprintf(output, " %2.2f%%", ((double)pnugget_path->data_time_interval_read[i].average_time / pnugget_path->data_time_read.average_time) * 100);
			}
			else
			{
				fprintf(output, " %2.2f%%", 0.0);
			}
			fprintf(output, "\n");

			fprintf(output, "%20s %6s ", " ", "Write");
			print_data_time_statistic(output, &pnugget_path->data_time_interval_write[i]);
			if(pnugget_path->data_time_write.average_time != 0)
			{
				fprintf(output, " %2.2f%%", ((double)pnugget_path->data_time_interval_write[i].average_time / pnugget_path->data_time_write.average_time) * 100);
			}
			else
			{
				fprintf(output, " %2.2f%%", 0.0);
			}
			fprintf(output, "\n");
		}
		fprintf(output, "\n");
	}

	// Free all dynamic allocated variables.
	struct dio_nugget_path* tmpdng_path;

	list_for_each_entry_safe(pnugget_path, tmpdng_path, &nugget_path_head, link)
	{
		list_del(&pnugget_path->link);
		free(pnugget_path->data_time_interval_read);
		free(pnugget_path->data_time_interval_write);
		free(pnugget_path);
	}
}

void print_data_time_statistic(FILE* stream, struct data_time* pdata_time)
{
	fprintf(stream, "%6d %2llu:%.10llu %2llu:%.10llu %2llu:%.10llu", pdata_time->count,
			SECONDS(pdata_time->average_time), NANO_SECONDS(pdata_time->average_time),
			SECONDS(pdata_time->max_time), NANO_SECONDS(pdata_time->max_time),
			SECONDS(pdata_time->min_time), NANO_SECONDS(pdata_time->min_time)
	       );
}

//---------------------------------------- pid statistic -------------------------------------------------//
//function for handling data structure for pid statistic
struct pid_stat_data* rb_search_psd(uint32_t pid){
	struct rb_node* n = psd_root.rb_node;
	struct pid_stat_data* ppsd = NULL;
	
	while(n){
		ppsd = rb_entry(n, struct pid_stat_data, link);

		if( pid < ppsd->pid )
			n = n->rb_left;
		else if( pid > ppsd->pid )
			n = n->rb_right;
		else 
			return ppsd;
	}
	return NULL;
}

struct pid_stat_data* __rb_insert_psd(struct pid_stat_data* newpsd){
	struct pid_stat_data* ret;
	struct rb_node** p = &(psd_root.rb_node);
	struct rb_node* parent = NULL;
	
	while(*p){
		parent = *p;
		ret = rb_entry(parent, struct pid_stat_data, link);

		if( newpsd->pid < ret->pid )
			p = &(*p)->rb_left;
		else if( newpsd->pid > ret->pid )
			p = &(*p)->rb_right;
		else
			return ret;
	}

	rb_link_node(&newpsd->link, parent, p);
	return NULL;
}

struct pid_stat_data* rb_insert_psd(struct pid_stat_data* newpsd){
	struct pid_stat_data* ret = NULL;
	if( (ret = __rb_insert_psd(newpsd) ) )
		return ret;
	rb_insert_color(&newpsd->link, &psd_root);
	return ret;
}

void __clear_pid_stat(struct rb_node* p){
	if( p->rb_left != NULL )
		__clear_pid_stat(p->rb_left);
	if( p->rb_right != NULL )
		__clear_pid_stat(p->rb_right);
	
	struct pid_stat_data* psd = rb_entry(p, struct pid_stat_data, link);
	free(psd);
}

void init_pid_statistic(){
}

void travel_pid_statistic(struct dio_nugget* pdng){
	struct pid_stat_data* ppsd = rb_search_psd(pdng->pid);
	if( ppsd == NULL ){
		ppsd = (struct pid_stat_data*)malloc(sizeof(struct pid_stat_data));
		ppsd->pid = pdng->pid;
		
		ppsd->data_time_read.min_time = (unsigned int)(-1);
		ppsd->data_time_read.max_time = 0;
		ppsd->data_time_read.total_time = 0;
		ppsd->data_time_read.count = 0;
		ppsd->data_time_read.average_time = 0;

		ppsd->data_time_write.min_time = (unsigned int)(-1);
		ppsd->data_time_write.max_time = 0;
		ppsd->data_time_write.total_time = 0;
		ppsd->data_time_write.count = 0;
		ppsd->data_time_write.average_time = 0;
		
		rb_insert_psd(ppsd);
	}
	
	uint64_t tmpt = 0;
	if( pdng->category & BLK_TC_READ ){
		tmpt = pdng->times[pdng->elemidx-1] - pdng->times[0];
		if( ppsd->data_time_read.min_time > tmpt )
			ppsd->data_time_read.min_time = tmpt;
		else if( ppsd->data_time_read.max_time < tmpt )
			ppsd->data_time_read.max_time = tmpt;
		ppsd->data_time_read.total_time += tmpt;
		ppsd->data_time_read.count ++;
	}
	else if( pdng->category & BLK_TC_WRITE ){
		tmpt = pdng->times[pdng->elemidx-1] - pdng->times[0];
		if( ppsd->data_time_write.min_time > tmpt )
			ppsd->data_time_write.min_time = tmpt;
		else if( ppsd->data_time_write.max_time < tmpt )
			ppsd->data_time_write.max_time = tmpt;
		ppsd->data_time_write.total_time = tmpt;
		ppsd->data_time_write.count ++;
	}
}

void process_pid_statistic(int ng_cnt){
	struct rb_node* node = NULL;

	fprintf(output,"%10s %6s %6s %12s %12s %12s \n", "pid", "Type", "No", "AverageTime", "MaxTime", "MinTime");
	node = rb_first(&psd_root);
	do{
		struct pid_stat_data* ppsd = NULL;
		ppsd = rb_entry(node, struct pid_stat_data, link);
		
		if( ppsd->data_time_read.count != 0 ){
			ppsd->data_time_read.average_time = 
				ppsd->data_time_read.total_time / ppsd->data_time_read.count;
		}
		if( ppsd->data_time_write.count != 0 ){
			ppsd->data_time_write.average_time = 
				ppsd->data_time_write.total_time / ppsd->data_time_write.count;
		}

		if( ppsd->data_time_read.min_time == (uint64_t)(-1) )
			ppsd->data_time_read.min_time = 0;
		if( ppsd->data_time_write.min_time == (uint64_t)(-1) )
			ppsd->data_time_write.min_time = 0;

		//printing
		fprintf(output, "%10"PRIu32" %6s %6d %2llu:%.10llu %2llu:%.10llu %2llu:%.10llu \n", 
			ppsd->pid, "Read", ppsd->data_time_read.count, 
			SECONDS(ppsd->data_time_read.average_time), NANO_SECONDS(ppsd->data_time_read.average_time),
			SECONDS(ppsd->data_time_read.max_time), NANO_SECONDS(ppsd->data_time_read.max_time),
			SECONDS(ppsd->data_time_read.min_time), NANO_SECONDS(ppsd->data_time_read.min_time)
		);

		fprintf(output, "%10s %6s %6d %2llu:%.10llu %2llu:%.10llu %2llu:%.10llu \n", 
			" ", "Write", ppsd->data_time_write.count,
			SECONDS(ppsd->data_time_write.average_time), NANO_SECONDS(ppsd->data_time_write.average_time),
			SECONDS(ppsd->data_time_write.max_time), NANO_SECONDS(ppsd->data_time_write.max_time),
			SECONDS(ppsd->data_time_write.min_time), NANO_SECONDS(ppsd->data_time_write.min_time)
		);
		fprintf(output, "\n");
	}while( (node = rb_next(node)) != NULL );

	//clear all pid tree
	struct rb_node* parent = psd_root.rb_node;
	__clear_pid_stat(parent);
}


//------------------- section statistics (for example)------------------------------//
#define MAX_MON_SECTION 10
static char mon_section[MAX_MON_SECTION][2];
static uint64_t mon_sec_time[MAX_MON_SECTION];
static int mon_sec_cnt[MAX_MON_SECTION];
static int mon_cnt = 0;

void add_monitored_section(char section[2]){
	if( mon_cnt+1 >= MAX_MON_SECTION )
		return;
	
	memcpy(mon_section[mon_cnt], section, 2);
	mon_cnt++;
}

int find_section(char* states, int mon_sec_num){
	if( mon_sec_num >= mon_cnt )
		return -1;

	int i=0;
	for(; i<MAX_ELEMENT_SIZE-1; i++){
		if( states[i] == 0 )
			break;
		if( states[i] == mon_section[mon_sec_num][0] &&
			states[i+1] == mon_section[mon_sec_num][1] )
			return i;
	}
	return -1;
}
			
void init_section_statistic(){
	memset(mon_section, 0, sizeof(char)*MAX_MON_SECTION*2);
	memset(mon_sec_time, 0, sizeof(uint64_t)*MAX_MON_SECTION);
	memset(mon_sec_cnt, 0, sizeof(mon_sec_cnt));
	mon_cnt = 0;
}

void travel_section_statistic(struct dio_nugget* pdng){
	int i=0, pos=0;
	for(; i<mon_cnt; i++){
		pos = find_section(pdng->states, i);
		if( i == -1 )
			continue;
		
		mon_sec_time[i] += (pdng->times[pos+1] - pdng->times[pos]);
		mon_sec_cnt[i] ++;
	}
}

void process_section_statistic(int ng_cnt){
	int i=0;
	for(; i<mon_cnt; i++){
		//calculate the average spending time for each section
		mon_sec_time[i] /= mon_sec_cnt[i];

		//print data
	}

	//clear data
}

//------------------- cpu statistics ------------------------------//

#define INIT_NUM_CPU 4
struct dio_cpu *diocpu;
int maxCPU = 0;

void create_diocpu(void)
{
	int i;

	// Create diocpu
	if(diocpu == NULL)
	{
		diocpu = (struct dio_cpu*)malloc(sizeof(struct dio_cpu) * INIT_NUM_CPU);
	}
	else
	{
		diocpu = (struct dio_cpu*)realloc(diocpu, sizeof(struct dio_cpu) * (maxCPU + INIT_NUM_CPU));
	}

	// Init members
	memset(diocpu + maxCPU, 0, sizeof(struct dio_cpu) * INIT_NUM_CPU);
	maxCPU += INIT_NUM_CPU;
}

void init_cpu_statistic(void)
{
	create_diocpu();
}

void itr_cpu_statistic(struct blk_io_trace* pbit)
{
	uint32_t category = pbit->action >> BLK_TC_SHIFT;

	// Is enough diocpu?
	while(maxCPU <= pbit->cpu)
	{
		create_diocpu();
	}
	
	// Distribute read/write data and point that.
	if(category & BLK_TC_READ)
	{
		diocpu[pbit->cpu].r_cnt++;
	}
	else if(category & BLK_TC_WRITE)
	{
		diocpu[pbit->cpu].w_cnt++;
	}
	else
	{
		diocpu[pbit->cpu].x_cnt++;
	}
}

void process_cpu_statistic(int bit_cnt)
{
	int i, tot;

	fprintf(output,"%4s %7s %8s %8s\n", "CPU", "Type", "COUNT", "RATE");

	for(i=0 ; i<maxCPU ; i++)
	{
		fprintf(output,"%4d %7s %8d %8lf\n",
			i, "R", diocpu[i].r_cnt, diocpu[i].r_cnt/(double)bit_cnt*100);
		fprintf(output,"%4s %7s %8d %8lf\n",
			" ","W",diocpu[i].w_cnt, diocpu[i].w_cnt/(double)bit_cnt*100);
		fprintf(output,"%4s %7s %8d %8lf\n",
			" ","unknown",diocpu[i].x_cnt, diocpu[i].x_cnt/(double)bit_cnt*100);

		tot = diocpu[i].r_cnt + diocpu[i].w_cnt + diocpu[i].x_cnt;
		fprintf(output,"%4s %7s %8d %8lf\n",
			" ","Total :",tot, tot/(double)bit_cnt*100);
		fprintf(output,"\n");
	}

	//clear data
	free(diocpu);
}

#if 0	// Replace other source
//------------------- cpu statistics ------------------------------//

#define INIT_NUM_CPU 4
struct dio_cpu *diocpu;
int maxCPU = 0;

void create_diocpu(void)
{
	int i;

	// Create diocpu
	if(diocpu == NULL)
	{
		diocpu = (struct dio_cpu*)malloc(sizeof(struct dio_cpu) * INIT_NUM_CPU);
	}
	else
	{
		diocpu = (struct dio_cpu*)realloc(diocpu, sizeof(struct dio_cpu) * (maxCPU + INIT_NUM_CPU));
	}

	// Init members
	memset(diocpu + maxCPU, 0, sizeof(struct dio_cpu) * INIT_NUM_CPU);
	for(i=0 ; i<INIT_NUM_CPU ; i++)
	{
		diocpu[maxCPU + i].data_time_read.min_time = -1;
		diocpu[maxCPU + i].data_time_write.min_time = -1;
	}
	maxCPU += INIT_NUM_CPU;
}

void init_cpu_statistic(void)
{
	create_diocpu();
}

void travel_cpu_statistic(struct dio_nugget* pdng)
{
	unsigned int nugget_time;
	struct data_time *pdata_time;

	// Is enough diocpu?
	while(maxCPU < pdng->idxCPU)
	{
		create_diocpu();
	}
	
	// Distribute read/write data and point that.
	if(pdng->category & BLK_TC_READ)
	{
		pdata_time = &diocpu[pdng->idxCPU].data_time_read;
	}
	else if(pdng->category & BLK_TC_WRITE)
	{
		pdata_time = &diocpu[pdng->idxCPU].data_time_write;
	}
	else
	{
		return ;
	}
	
	// Process datas.
	nugget_time = pdng->times[pdng->elemidx] - pdng->times[0];
	pdata_time->count++;
	pdata_time->total_time += nugget_time;
	if(pdata_time->max_time < nugget_time)
	{
		pdata_time->max_time = nugget_time; 
	}
	if(pdata_time->min_time > nugget_time)
	{
		pdata_time->min_time = nugget_time; 
	}
}

void process_cpu_statistic(int ng_cnt)
{
	int i;

	// Calculate average time.
	for(i=0 ; i<maxCPU ; i++)
	{
		if(diocpu[i].data_time_read.count != 0)
		{
			diocpu[i].data_time_read.average_time = diocpu[i].data_time_read.total_time / diocpu[i].data_time_read.count;
		}
		if(diocpu[i].data_time_write.count != 0)
		{
			diocpu[i].data_time_write.average_time = diocpu[i].data_time_write.total_time / diocpu[i].data_time_write.count;
		}
		// if min_time is -1 that initializing value for calculating min_time, change that to 0.
		if(diocpu[i].data_time_read.min_time == -1)
		{
			diocpu[i].data_time_read.min_time = 0;
		}
		if(diocpu[i].data_time_write.min_time == -1)
		{
			diocpu[i].data_time_write.min_time = 0;
		}
	}
}

void print_cpu_statistic(void)
{
	int i;

	printf("%4s %6s %6s %12s %12s %12s \n", "CPU", "Type", "No", "AverageTime", "MaxTime", "MinTime");
	for(i=0 ; i<maxCPU ; i++)
	{
		fprintf(output, "%4d %6s %6d %2llu:%.10llu %2llu:%.10llu %2llu:%.10llu \n", i, "Read", diocpu[i].data_time_read.count,
			SECONDS(diocpu[i].data_time_read.average_time), NANO_SECONDS(diocpu[i].data_time_read.average_time),
			SECONDS(diocpu[i].data_time_read.max_time), NANO_SECONDS(diocpu[i].data_time_read.max_time),
			SECONDS(diocpu[i].data_time_read.min_time), NANO_SECONDS(diocpu[i].data_time_read.min_time)
		);
		fprintf(output, "%4s %6s %6d %2llu:%.10llu %2llu:%.10llu %2llu:%.10llu \n", " ", "Write", diocpu[i].data_time_write.count,
			SECONDS(diocpu[i].data_time_write.average_time), NANO_SECONDS(diocpu[i].data_time_write.average_time),
			SECONDS(diocpu[i].data_time_write.max_time), NANO_SECONDS(diocpu[i].data_time_write.max_time),
			SECONDS(diocpu[i].data_time_write.min_time), NANO_SECONDS(diocpu[i].data_time_write.min_time)
		);
		fprintf(output, "\n");
	}
}

void clear_cpu_statistic(void)
{
	free(diocpu);
}
#endif
