/*
	By Sirus Shahini
	~cyn
*/

/*
	WARNING:	This file is the most fragile part of this fuzzer.
			A tiny mistake in this code can subvert the whole logic
			based on which the fuzzer works and even may crash the
			library in a way that can be very hard to debug.
			If you want to work on Zharf's code, it's suggested to
			leave this file as is.
*/


#include "libzh.h"



u8 fserv_active = 0;
void * shm;

u8 debug_print=0;
//#define DEBUG_MODE


u64 *global_lock   ;
/*
	Not called in any performance critical part.
*/
void zrep(char *fmt, ...){
	char s_format[2048];

	if (!debug_print) return;

	strcpy(s_format,CGREEN "[-] Lib: "CNORM);
	strcat(s_format,fmt);
	strcat(s_format,"\n");
    va_list argp;
    va_start(argp,s_format);
    vprintf(s_format,argp);
    va_end(argp);

}

void zexit(char *fmt, ...){
	char err_format[2048];

	strcpy(err_format,CRED "[!]" CNORM " Lib: ");
	strcat(err_format,fmt);
	strcat(err_format,"\n");
    va_list argp;
    va_start(argp,err_format);
    vprintf(err_format,argp);
    va_end(argp);
	exit(-1);
}
void save_memory(char *msg){
	char fname[255];
	FILE *f;

	sprintf(fname,"/tmp/lib_shared_mem_%016lx_%s",(u64)shm,".");

	f=fopen(fname,"w");

	if (!f){
		zexit("Can't open memory");
		return;
	}

	if (fwrite(shm,1,SHM_SIZE,f)<SHM_SIZE){
		printf("Incomplete memory save\n");
	}
	fclose(f);
	printf("LIB: Memroy saved in %s\n",fname);
}
void force_write_exit(u8 flush,char *fmt, ...){
	char err_format[2048];
	int n;
	char out[512];

	if (flush){
		/*
			discard buffered data
		*/
		fflush(stdout);
	}

	n=open("/dev/tty",O_WRONLY);
	if (n!=1){
		dup2(n,1);
		close(n);
	}

	sprintf(err_format,CRED "[!]" CNORM " Lib: [Target %d] ",getpid());
	strcat(err_format,fmt);
	strcat(err_format,"\n");
    va_list argp;
    va_start(argp,err_format);
    vsprintf(out,err_format,argp);
    va_end(argp);

    save_memory(out);
    fflush(stdout);

    write(1,out,strlen(out));

	exit(-1);
	printf("LIB: not exited\n");
	//kill(getpid(),SIGTERM);
}

//#define DEBUG_MODE
#ifdef DEBUG_MODE
#define TERMINATE(fl,fmt,...) force_write_exit(fl,fmt __VA_OPT__(,) __VA_ARGS__)
#else
#define TERMINATE(fl,fmt,...) exit(-1)
#endif


/**************** static lib variables start *****************/

struct tree *trace_tree;

struct block_info *blocks;

struct node *node_pool;
struct child_ptr *child_pool;


struct node *current_node;

/**************** static lib variables end ********************/



/****** Protected shared memory variables start **************/


long *cur_block ;

u64 *cur_node_in_pool;
u64 *cur_child_in_pool;


/*********** Protected shared memory variables end ***********/



struct node *ret_new_node(){
	return &node_pool[(*cur_node_in_pool)++];

}

struct node *alloc_node(ID_SIZE id){
	struct node* new_node = ret_new_node();

#ifdef DEBUG_MODE
	if (new_node->id || new_node->parent || new_node->children){
		TERMINATE(1,"Stale node %08x/%016lx/%016lx for %08x"
						,new_node->id,new_node->parent,new_node->children,id);
	}
#endif

	new_node->id=id;
	return new_node;

}
struct child_ptr *alloc_child_ptr(struct node *child_node){
	struct child_ptr* new_child=&child_pool[(*cur_child_in_pool)++];

#ifdef DEBUG_MODE
	if (!child_node){
		TERMINATE(1,"alloc_child_ptr: Invalid argument");
	}
	if (!new_child){
		TERMINATE(1,"alloc_child_ptr: Invalid new child ");
	}
#endif

	new_child->next_child=0;
	new_child->child_node=child_node;
	return new_child;
}

struct block_info* search(ID_SIZE id){
	long mid;
	long low=0,high=*cur_block;

	while(low<=high){
		mid = (low+high)/2;

		if (blocks[mid].id==id){
			return &blocks[mid];
		}
		else if(id < blocks[mid].id){
			high = mid-1;
		}else{
			low = mid+1;
		}
	}
	return 0;
}

struct child_ptr *add_child(struct node *parent, struct node *child_node){
	struct child_ptr *p = parent->children;
	struct child_ptr* new_child;

#ifdef DEBUG_MODE
	if (!parent || !child_node){
		TERMINATE(1,"add_child: Invalid %016lx %016lx",(u64)parent,(u64)child_node);
	}

#endif

	if (p==0){
		new_child = alloc_child_ptr(child_node);
		parent->children = new_child;
		trace_tree->total_children++;
		return new_child;
	}

	while(1){
		if (p->child_node == child_node){
			return 0;
		}
		if (!p->next_child)break;
		p=p->next_child;
	}

	new_child = alloc_child_ptr(child_node);
	p->next_child=new_child;

	trace_tree->total_children++;

	return new_child;

}
struct node * add_node(ID_SIZE new_id,ID_SIZE parent_id,BLOCK_INFO_SIZE blkinfo){
	struct block_info * cur,*tmp_pointer;
	struct block_info new_block,temp;
	struct node *new_node;
	struct node *parent_node;
	struct node * pparent;


	if (trace_tree->count ==0){

		*cur_block = -1 ;
		*cur_node_in_pool=0;
		*cur_child_in_pool=0;
		current_node = 0;

		new_node = alloc_node(new_id);
		new_block.ptr = new_node;
		new_block.id = new_id;
		blocks[++(*cur_block)] = new_block;
		trace_tree->count = 1;
		trace_tree->root = new_node;
		zrep("initialized root %lu\n",new_id);
		current_node = new_node;
		trace_tree->total_hits++;
		(current_node)->hits++;
		return new_node;
	}


	tmp_pointer = search(parent_id);

#ifdef DEBUG_MODE
	if (!tmp_pointer){
		TERMINATE(1,"add_node: Invalid parent ID \"%016lx\" corrupted tree",parent_id);
	}
#endif

	parent_node = tmp_pointer->ptr;

#ifdef DEBUG_MODE
	if (!parent_node){
		TERMINATE(1,"add_node: Invalid parent, corrupted tree");
	}
#endif

	pparent = parent_node->parent;
	if (parent_node->id == new_id){
		(current_node)->info=blkinfo;
		return current_node;
	}


	if ( (cur=search(new_id)) ){
		(current_node) = cur->ptr;
#ifdef DEBUG_MODE
		if (!(current_node)){
			TERMINATE(1,"add_node: linear node doesn't have node ptr for id %08x",new_id);
		}
#endif


		if (pparent){
			if (pparent->id == new_id){
				/*
					We're done here
					This can be a function return (nested)
					or jump back to begininng of a simple
					loop.
					In either case we don't want two nodes
					have two edges to each other.
					save block info and return immediatly.

				*/
			}else{

				if ( ( blkinfo & BLOCK_TYPE ) ==0){
					if (add_child(parent_node,current_node)){
						//new edge
					}else{
						//edge exists
					}

					(current_node)->hits++;
					trace_tree->total_hits++;
				}

			}
		}

		(current_node)->info=blkinfo;

		return current_node;
	}

	new_block.id = new_id;

	if (!parent_node)
		return 0;

#ifdef DEBUG_MODE
	if (blkinfo && BLOCK_TYPE==1){
		/*
			This MUST not be a nested block
		*/
		TERMINATE(1,"Nested block visited as new block: %016lx",new_id);
	}
#endif

	blocks[++(*cur_block)] = new_block;
	cur = &blocks[*cur_block];

	while (cur != blocks){
		if ( (cur-1)->id > cur->id){
			temp = *cur;
			*cur = *(cur-1);
			*(cur -1) = temp;
			cur--;
		}
		else{
			break;
		}
	}

	new_node = alloc_node(new_id);

#ifdef DEBUG_MODE
	if (!new_node){
		TERMINATE(1,"add_node: Got invalid node");
	}
	if (cur->id != new_id){
		TERMINATE(1,"add_node: cur not pointing to the original entry");
	}
#endif

	cur->ptr = new_node;
	new_node->parent = parent_node;
	new_node->info=blkinfo;

	if (add_child(parent_node,new_node)){
		//new edge
	}else{
		//edge exists (MUST NOT HAPPEN HERE)

#ifdef DEBUG_MODE
		TERMINATE(1,"add_node: Unexpected edge.");
#endif
	}
	trace_tree->total_hits++;
	trace_tree->count++;
	current_node = new_node;
	(current_node)->hits++;


/*
#define get_node_mark(info_byte)	(info_byte & BLOCK_MARKED)
		if (get_node_mark((current_node)->info))
		zexit("LIB:  MARKED TREE DETECTED ");
*/

	return new_node;
}


/****** End Tree management ***********/

/*
	If a SEGFAULT happens in lib first check the map size
	defined in head.h since it may be too small for
	your target program.
*/
void sigf_handler(int signal, siginfo_t *si, void *ucontext){
	void *buf[100];
	int n=0;
	char **names;
	int i;

	n=backtrace(buf,100);

	names=backtrace_symbols(buf,n);

	fflush(stdout);
	printf("\n\n******* " CRED "LIBRARY FATAL STATE (SIGSEGV) " CNORM "*******\n");

	for (i=0;i<n;i++){
		printf("> %s\n",names[i]);
	}

	TERMINATE(0,"Address fault: %016lx",(u64)si->si_addr);
	//exit(1);
}


int ulock(void * uadr){
    u64 volatile r =0 ;
    asm volatile(
        "xor %%rax,%%rax\n"
        "mov $1,%%rbx\n"
        "lock cmpxchg %%ebx,(%1)\n"
        "sete (%0)\n"
        : : "r"(&r),"r" (uadr)
        : "%rax","%rbx"
    );
    return (r) ? 1 : 0;
}

#define MULT_THREAD_SUPPORT

#ifdef MULT_THREAD_SUPPORT

#define ACQUIRE_LOCK while(!ulock((void *)global_lock));
#define RELEASE_LOCK *global_lock = 0;

#else

#define ACQUIRE_LOCK ;
#define RELEASE_LOCK ;

#endif

void log_block(ID_SIZE id,BLOCK_INFO_SIZE blkinfo){

#define add_node_locked(x) 	ACQUIRE_LOCK\
							add_node(id,x,blkinfo);\
							RELEASE_LOCK

	if (current_node){
		add_node_locked((current_node)->id);
	}else{
		add_node_locked(0);
	}
}


/*
	Busy loop function
	we will not exit from this function
*/
u8 run_fserver(){
	int shm_id;
	int n;
	char command;
	int child_id;
	int child_exit_status;
	void *shm_adr;
	void *pools_start;

	n =read(FD_IN,&shm_id,4);

	if (n<4){
		zexit("FATAL: Can't read shared memory id\n");
	}

	n =read(FD_IN,&shm_adr,8);

	if (n<8){
		zexit("FATAL: Can't read shared memory adr\n");
	}
	shm = shmat(shm_id,shm_adr,0);
	if (!shm){
		zexit("FATAL: Can't attach to shared memory\n");
	}
	printf("Requested %016lx Got %d %016lx\n",(u64)shm_adr,shm_id,(u64)shm);
	if (shm_adr != shm){
		zexit("FATAL: Address mismatch\n");
	}
	printf("[-] Lib: shm: %d %016lx\n",shm_id,(u64)shm);


	/*
		Ok we're ready to receive commands from parent
		let it know and go to busy wait
	*/
	write(FD_OUT,".",1);

	fserv_active = 1;

	pools_start = shm + 256;

	blocks= (struct block_info *) pools_start;
	node_pool = (struct node *)(shm+(u64)(SHM_SIZE>>2));
	child_pool = (struct child_ptr*)(shm+(u64)(3*(SHM_SIZE>>2)));


	trace_tree= (struct tree*)(shm + LOCK_DELTA + PROT_VARS_DELTA);

	/*
		Init protected shared vars
	*/

	global_lock = shm;
	cur_block = (long *)(shm + LOCK_DELTA );
	cur_node_in_pool = (u64 *)(shm + LOCK_DELTA + 8);
	cur_child_in_pool = (u64 *)(shm + LOCK_DELTA + 16);

	*cur_block = -1;
	/* Fuzzer must have already zeroed these*/
	*cur_node_in_pool = 0;
	*cur_child_in_pool = 0;
	current_node = 0;
	*global_lock = 0;
	/******************************************/

	while(1){
		n =read(FD_IN,&command,1);

		if (n<1){
			zexit("FATAL: Can't read command");
		}
		zrep("%d recieved fork cmd %c\n",n,command);
		child_id=fork();
		if (child_id<0){
			zexit("FATAL: Can't fork");
		}
		if (child_id){

			n=write(FD_OUT,&child_id,4);
			if (n<4){
				zexit("FATAL: Can't write response; %d %s\n",n,strerror(errno));
			}

			if (waitpid(child_id,&child_exit_status,0)<0){
				zexit("FATAL: waitpid\n");
			}

			n=write(FD_OUT,&child_exit_status,4);

			if (n<4){
				printf("%d %s\n",n,strerror(errno));
				zexit("FATAL: Can't write response\n");
			}
		}else {
			close(FD_IN);
			close(FD_OUT);
			return 0;
		}

	}

}

int lib_zh_entry(ID_SIZE id,BLOCK_INFO_SIZE blkinfo){
	int save_errno;

	save_errno = errno;

	if (!fserv_active){
		if (fcntl(FD_IN,F_GETFD)==-1){
			errno = save_errno;
			return 0;
		}
		zrep("Initializing starter\n");
		run_fserver();
	}

	log_block(id,blkinfo);

	errno = save_errno;

	return 0;
}
