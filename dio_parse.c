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
	char type[5];	//type of bit who was requested
	int size;	//size of nugget
	uint64_t sector;	//sector number of bit who was requested. is it really need?
	struct dio_nugget* mlink;	//if it was merged, than mlink points the other nugget
	int ngflag;
};

// list node of blk_io_trace
// it just maintain the time ordered bits
struct bit_entity{
	struct list_head link;
	
	struct blk_io_trace bit;
};

struct dio_nugget_path
{
	struct list_head link;

	char states[MAX_ELEMENT_SIZE];
	int count_nugget;
	int count_read;
	int count_write;
	unsigned int total_time;
	unsigned int average_time;
	unsigned int max_time;
	unsigned int min_time;
	int* interval_time;
};

/*--------------	function interfaces	-----------------------*/
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

void print_path_statistic(void);
struct dio_nugget_path* find_nugget_path(struct list_head* nugget_path_head, char* states);

/*--------------	global variables	-----------------------*/
#define MAX_FILEPATH_LEN 255
static char respath[MAX_FILEPATH_LEN];	//result file path
static struct rb_root rben_root;	//root of rbentity tree
static struct list_head biten_head;

/*--------------	function implementations	---------------*/
int main(int argc, char** argv){
	INIT_LIST_HEAD(&biten_head);
	rben_root = RB_ROOT;

	int ifd = -1;
	int rdsz = 0;
	char pdubuf[256];

	strncpy(respath, "dioshark.output", MAX_FILEPATH_LEN);

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
			DBGOUT(">end read\n");
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
		
		if( (pbiten->bit.action >> BLK_TC_SHIFT) == BLK_TC_NOTIFY )
			continue;
			
#ifdef DEBUG
			DBGOUT("============================ \n");
			DBGOUT("sequence : %u \n", pbiten->bit.sequence);
			DBGOUT("time : %5d.%09lu \n", (int)SECONDS(pbiten->bit.time), (unsigned long)NANO_SECONDS(pbiten->bit.time));
			DBGOUT("sector : %llu \n", pbiten->bit.sector);
			DBGOUT("bytes : %u \n", pbiten->bit.bytes);
			char c = GET_ACTION_CHAR(pbiten->bit.action);
			DBGOUT("action : %x(%c) \n", pbiten->bit.action,c);
			DBGOUT("pid : %u \n", pbiten->bit.pid);
			DBGOUT("device : %u \n", pbiten->bit.device);
			DBGOUT("cpu : %u \n", pbiten->bit.cpu);
			DBGOUT("error : %u \n", pbiten->bit.error);
			DBGOUT("pdu_len : %u \n", pbiten->bit.pdu_len);
			DBGOUT("length of read : %d \n", rdsz);
			DBGOUT("\n");
#endif	
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

	print_path_statistic();

	//clean all list entities
	return 0;
err:
	if( ifd < 0 )
		close(ifd);
	if( pbiten != NULL )
		free(pbiten);
	return 0;
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
	if( pdngbuf->elemidx == 0 )
		pdngbuf->size = pbit->bytes;

	handle_action(pbit->action, pdngbuf);
	pdngbuf->category = pbit->action >> BLK_TC_SHIFT;
	pdngbuf->elemidx++;
}

void handle_action(uint32_t act, struct dio_nugget* pdng){
	struct dio_nugget* ptmpng = NULL;
	struct dio_nugget* newng = NULL;
	struct dio_rbentity* prben = NULL;

	char actc = GET_ACTION_CHAR(act);
	pdng->states[pdng->elemidx] = actc;
	DBGOUT("action %x(%c), sector %"PRIu64", size %d\n", act, actc, pdng->sector, pdng->size);
	

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

void print_path_statistic(void)
{
	struct rb_node* node;
	struct list_head nugget_path_head;
	struct dio_nugget_path* pnugget_path;

	INIT_LIST_HEAD(&nugget_path_head);

	node = rb_first(&rben_root);
	do
	{
		struct dio_rbentity* prbentity;

		prbentity = rb_entry(node, struct dio_rbentity, rblink);

		struct dio_nugget* pdng;

		list_for_each_entry(pdng, &prbentity->nghead, nglink)
		{
			char* pstates;
			uint64_t* ptimes;
			int* pelemidx;
			int i;
			int nugget_time;

			pnugget_path = find_nugget_path(&nugget_path_head, pdng->states);
			if(pnugget_path == NULL)
			{
				pnugget_path = (struct dio_nugget_path*)malloc(sizeof(struct dio_nugget_path));
				memset(pnugget_path, 0, sizeof(struct dio_nugget_path));
				pnugget_path->min_time = -1;
				strncpy(pnugget_path->states, pdng->states, MAX_ELEMENT_SIZE);

				list_add(&(pnugget_path->link), &nugget_path_head);
//				pnugget_path->interval_time = (int*)malloc(sizeof(int) * (pdng->elemidx-1));
			}
			if(pdng->category & BLK_TC_READ)
			{
				pnugget_path->count_read++;
			}
			if(pdng->category & BLK_TC_WRITE)
			{
				pnugget_path->count_write++;
			}

			pnugget_path->count_nugget++;
			nugget_time = pdng->times[pdng->elemidx] - pdng->times[0];
			pnugget_path->total_time += nugget_time;
			if(pnugget_path->max_time < nugget_time)
			{
				pnugget_path->max_time = nugget_time;
			}
			if(pnugget_path->min_time > nugget_time)
			{
				pnugget_path->min_time = nugget_time;
			}
		}
		pnugget_path->average_time = pnugget_path->total_time / pnugget_path->count_nugget;
	}while((node = rb_next(node)) != NULL);

	printf("%20s %8s %8s %4s %12s %12s %12s \n", " ", "횟수", "읽기횟수", "쓰기횟수", "평균수행시간", "최대수행시간", "최소수행시간");
	list_for_each_entry(pnugget_path, &nugget_path_head, link)
	{

		printf("%20s %4d %8d %8d %2llu:%.9llu %2llu:%.9llu %2llu:%.9llu \n", pnugget_path->states, pnugget_path->count_nugget,
			pnugget_path->count_read, pnugget_path->count_write,
			SECONDS(pnugget_path->average_time), NANO_SECONDS(pnugget_path->average_time),
			SECONDS(pnugget_path->max_time), NANO_SECONDS(pnugget_path->max_time),
			SECONDS(pnugget_path->min_time), NANO_SECONDS(pnugget_path->min_time)
		);
	} 
}
