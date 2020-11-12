/*
	By Sirus Shahini
	~cyn
*/


#include "head.h"
#include "hash.h"

char *target_path;
char *input_dir;
char *output_dir;
char **target_argv;


int cmd_send[2];
int response_recv[2];
#define COUT cmd_send[1]
#define RIN	response_recv[0]
//#define BUILD_GRAPH
u8 should_store_graph=0;

#define ERR_TMOUT EAGAIN

int dev_null;
int feed_fd;

int file_feed;
char *feed_file_path;

int shm_id = -1;
void *shm_adr=0;
void *shm_end;
int starter_id;

char CURRENT_INPUT[] = "current_input";
char TMP_INPUT[] = "tmp_input";

#define MAX_INPUT_SIZE		(1<<15)	//32KB
#define MIN_INPUT_SIZE		(16)
u8 mut_map[MAX_INPUT_SIZE];
#define MAX_KEYWORDS		32
#define MAX_KW_SIZE			16
struct keyword {
	u8 kw[MAX_KW_SIZE];
	u8 size;
} keywords[MAX_KEYWORDS];
u8 kw_index = 0;


#define DICT_MAX_KEYWORDS		1024
#define DICT_MAX_KW_SIZE	32
char *dict_kws[DICT_MAX_KEYWORDS];
char *dict_file=0;
int dict_kw_count=0;

u32 current_csum;
u32 last_csum;
u8 need_csum;

int gcount =0 ;
int save_i_count = 0;
u8 sort_low_prio = 1;

u8 net_mode=0;
int tcp_port;

ID_SIZE dfs_list[NODES_MAX];
long dl_index=-1;
u32 graph_e_count=0;


int crash_rep=0;

#define MAX_EDGES_VISIBLE 200
#define GRAPH_FILES_COUNT	8

struct tree *shared_trace_tree;


#define MAX_LOCAL_BLOCKS	NODES_MAX
struct block_info_local{
	ID_SIZE id;
	u64 hits;
} sorted_blocks[MAX_LOCAL_BLOCKS];
long block_ind = -1;


int target_id;
int target_timedout=0;
#define TRG_EX_NORMAL	1
#define TRG_EX_TMOUT	2
#define TRG_EX_CRASH	3
#define TRG_SOFT_CRASH	4
#define TRG_NET_MODE	10

#define MAX_TIMEOUT_VAL_INIT 100000
#define MAX_TIMEOUT_VAL_RUN 90000
#define MIN_TIMEOUT_VAL 20000
#define TOI_RATE	2


u64 active_timeout = MAX_TIMEOUT_VAL_INIT ;
u64 active_timeout_sav;


long user_timeout=-1;

u8 save_soft_crash=0;

#define CONNECT_WAIT	100000
#define CONN_MAX_RETRIES	5
#define RECV_WAIT		20000
int net_sock=-1;
struct sockaddr_in target_saddr;
char *target_ip = "127.0.0.1";

u32 input_count = 0;

#define LIVE_REP_FILE "/var/www/html/zharflive/zharf_live"
//#define LIVE_STAT

#define STAT_ENTRIES_FILE	"stat_entries"

char stat_line[255];
u8 use_term_gui = 1;
u64 total_crashes=0;
u64 soft_crashes=0;
u64 unique_soft_crashes=0;
u64 unique_crashes=0;
int mut_input_saved=0;

char current_stat[255];
u64 _st_bl,_st_indp,_st_nes;
u8 brefr_freq = 20;
u8 brefr_freq_counter=0;
u8 zharf_init_state = 1;

s8 set_8_ints[] = {_8_ints};
s16 set_16_ints[] = {_8_ints , _16_ints};
s32 set_32_ints[] = {_8_ints , _16_ints , _32_ints};

u8 has_corrupted_shm=0;

//***************** Debug Definitions *************************

struct node *_debug_node;
u8 debug_mode = 0;
int debug_exit_code;
int debug_exit_stat;
u8 *debug_data;
size_t debug_data_size;

u64 debug_rec_ind = 0;
u64 debug_rec_dir = 0;
#define RECORD_FEEDS
u8 should_save_mem = 0;
u8 coverage_only = 0;
u8 state_slow_warn=0;
//***************************************************************


int perf_check_req;

int perf_check = 0;

u8 queue_hit_sl=0;

u8 cov_show_only = 0;

char * cmt ;

int attached_core;

#define CRASH_MAX	4096
u32 crash_sums[4096];
int crash_sums_index = 0;

#define MAX_INTR_LOCS	1024
#define MIN_INTR_LOC_COUNT 8

struct inp_intr_locs{
	int intr_locs_index;
	size_t intr_locs[MAX_INTR_LOCS];
};

u8 add_to_inputs = 0;

u64 *lib_lock;

u8 save_net=0;
int save_net_i = 0;
#define NET_FILE "debug/net/net_file"

time_t start_time;

#define INPUT_MAX			8000

struct input_val{
	char i_path[MAX_PATH];
	u8 initial;
	int depth;
	u64 total_blocks;
	u64 total_hits;
	u32 hash;
	u8 prio;
	u8 passed;
	u64 leaves;
	struct inp_intr_locs *i_intr_locs;
	u8 fixed_loc;
	u8 marked;
};

u8 lpq_balance =1 ;
u8 visited_lp=0;

u8 marked_tree=0;


u64 total_covered=0;
u64 total_exec=0;


u64 nested_counter=0;
u64 indp_counter=0;

u64 total_target_hits=0;

u64 last_trace_nodes=0;

u64 last_trace_leaves=0;

int last_crash_sig;
u8 last_crash_mut;

#define SHOULD_SKIP_COUNT	100
u32 skip_nodes=0;

u8 target_mult_threaded = 0;

struct input_val input_queue[INPUT_MAX];

int queue_ind;
#define last_added_q_i (queue_ind-1)
int queue_use_ind;

int max_depth=0;

int min_depth=10000;

u8 depth_grew=0;


u64 max_coverage_tree_nodes=0;
u8 invd_tree_nodes_grew = 0;

int output_count=0;

u8 enable_custom_cleanup = 0;
/*
	User's custom cleanup commands here.
	Example:
		{"rm /tmp/file1","mkdir ~/test"}
*/
char * cleanup_cmds[]={""};


/**************************** PRIORITY MODEL DEFINITIONS HERE *******************/

/*
	Tree Depth First : TDF : 0
	Tree Nodes First : TNF : 1
	Tree No Sort     : TNS : 2

	Add more priority models identifiers here
*/
u8 pm_mode = 0;
char *pm_str=0;
#define DEFAULT_PM_STR	"TDF"

#define MLPSD_ALLOWED	2

#define LPSD_MAX_DEPTH	2048
u8 LPSD_queue[LPSD_MAX_DEPTH];
u8 LPSD_queue_wait[LPSD_MAX_DEPTH];


#define MLPSC_ALLOWED	2


#define LPSC_MAX_NODES	(1<<16)
u8 *LPSC_queue;
u8 *LPSC_queue_wait;

u64 last_exec_inq=0, last_etime_inq=0;

struct sig_descriptor{
	int id;
	char name[20];
};
#define SIG_SET_SIZE	32
struct sig_descriptor sig_set[SIG_SET_SIZE]={
		{1,		"SIGHUP"	},
		{2,		"SIGINT"	},
		{3,		"SIGQUIT"	},
		{4,		"SIGILL"	},
		{5,		"SIGTRAP"	},
		{6,		"SIGABRT"	},
		{7,		"SIGBUS"	},
		{8,		"SIGFPE"	},
		{9,		"SIGKILL"	},
		{10,	"SIGUSR1"	},
		{11,	"SIGSEGV"	},
		{12,	"SIGUSR2"	},
		{13,	"SIGPIPE"	},
		{14,	"SIGALRM"	},
		{15,	"SIGTERM"	},
		{16,	"SIGSTKFLT"	},
		{17,	"SIGCHLD"	},
		{18,	"SIGCONT"	},
		{19,	"SIGSTOP"	},
		{20,	"SIGTSTP"	},
		{21,	"SIGTTIN"	},
		{22,	"SIGTTOU"	},
		{23,	"SIGURG"	},
		{24,	"SIGXCPU"	},
		{25,	"SIGXFSZ"	},
		{26,	"SIGVTALRM"	},
		{27,	"SIGPROF"	},
		{28,	"SIGWINCH"	},
		{29,	"SIGIO"		},
		{30,	"SIGPWR"	},
		{31,	"SIGSYS"	},
		{32,	"SIGRTMIN"	}


};

/*******************************************************************************/

void terminate_units(){

	use_term_gui = 0;

	if (target_id>0){
		kill(target_id,SIGKILL);
	}
	if (starter_id){
		kill(starter_id,SIGKILL);
	}


	if (shm_adr){

		if (shmctl(shm_id,IPC_RMID,0)==-1){
			printf(CRED"Warning: Couldn't release shared memory.\n"CNORM);
		}else{
			printf("Released memory\n");
		}
	}
	/*
		else we're exiting at initialization
		phase and memory has not been allocated.
	*/

	/*
		All file cleanups here
	*/
	//unlink(CURRENT_INPUT);
	printf(SC);
}
char *convert_time(char *ts){
	time_t cur_time;
	long h,m,s;

	time(&cur_time);
	cur_time-=start_time;

	h=cur_time/3600;
	cur_time -= 3600*h;

	m=cur_time/60;
	s=cur_time-60*m;

	sprintf(ts,"%02ld:%02ld:%02ld",h,m,s);

	return ts;
}


void dump_hex(u8 *buf,u8 size,int start,int end){
    int i;
    int last=0;
    char tmp[16];
    char sect[16];
    char *outbuf= malloc(2048);

    outbuf[0] = 0;
    for (i=0;i<size;i++){
    	if (i==start){
    		strcpy(sect,CRED);

    	}else if (i==end){
    		strcpy(sect,CNORM);
    	}else{
    		strcpy(sect,"");
    	}
        sprintf(tmp,"%02X ",(u8)*((u8*)(buf)+i));
        strcat(sect,tmp);
        strcat(outbuf,sect);
        last+=3;
        if (i%8==7) strcat(outbuf,"    ");
        if (i%16==15 || i==size-1) {
            printf("%s\n",outbuf);
            outbuf[0] = 0;
        }
    }
    free(outbuf);
    printf("\n");
}
void rep_use_time(){
	char ts[128];

	convert_time(ts);
	printf("Total time:  %s\n",ts);
}

void print_queue(){
	int i;

	for (i=0;i<queue_ind;i++){
		if (_st_indp)
			printf ("Q%d: \n\tdepth:%d %s prio=%d coverage=%lf nodes:%lu hits:%lu\n",i,
									input_queue[i].depth,input_queue[i].i_path,input_queue[i].prio,
									(double)input_queue[i].total_blocks/_st_indp,input_queue[i].total_blocks,
									input_queue[i].total_hits);
		else
			printf ("Q%d: \n\tdepth:%d %s prio=%d coverage=%s nodes:%lu hits:%lu\n",i,
									input_queue[i].depth,input_queue[i].i_path,input_queue[i].prio,
									"N/A",input_queue[i].total_blocks,
									input_queue[i].total_hits);
	}
}
void zexit(char *fmt, ...){
	char err_format[2048];


	strcpy(err_format,CRED "[!]" CNORM " Fuzzer: ");
	strcat(err_format,fmt);
	strcat(err_format,"\n");
	va_list argp;
	va_start(argp,err_format);
	vprintf(err_format,argp);
	va_end(argp);
	terminate_units();
	printf(DStop);

	if (!zharf_init_state)
		rep_use_time();

	exit(-1);
}

void rep(u8 warn, char *fmt, ...){
	char msg_format[2048];
	u8 should_print=0;

	if (zharf_init_state || !use_term_gui){
		should_print = 1;
	}
	if (!warn){
		strcpy(msg_format,CGREEN "[-] " CNORM );
	}
	else{
		strcpy(msg_format,CYELLOW "[W] " CNORM );

	}
	strcat(msg_format,fmt);
	va_list argp;

	if (should_print)
		strcat(msg_format,"\n");

	va_start(argp,msg_format);


	if (!should_print){
		if (!warn)
    		vsprintf(stat_line,msg_format,argp);
	}
	else{
		vprintf(msg_format,argp);
	}
	if (warn){
	    	/*
	    		In gui mode this is the only place that we
	    		want to see fuzzer warnings.
	    		Reserve stat line for rep.
	    	*/
		vsprintf(current_stat,msg_format,argp);
	}
	va_end(argp);

}


#define zrep(fmt,...) rep(0,fmt __VA_OPT__(,) __VA_ARGS__)
#define zwarn(fmt,...) rep(1,fmt __VA_OPT__(,) __VA_ARGS__)

#define SPACE(n) do{\
					int i;\
					for (i=0;i<n;i++) printf(" ");\
				 }while(0);


void clear_warn(){
	if (net_mode)
		strcpy(current_stat,CGREEN"NORMAL [Network Mode]"CNORM);
	else
		strcpy(current_stat,CGREEN"NORMAL"CNORM);
}
char *exec_speed(char *cs){
	struct timespec ctime;

	u64 cur_timeus;
	u64 espeed;
	double distance_s;

	clock_gettime(CLOCK_REALTIME,&ctime);
	cur_timeus= ctime.tv_sec*1000000 + ctime.tv_nsec/1000;
	distance_s = (cur_timeus-last_etime_inq)/1000000.0;


	if (distance_s > 0.0){
		espeed = (u64)((total_exec-last_exec_inq)/distance_s);
		sprintf(cs,"%lu/sec",espeed);
		brefr_freq = espeed/10;
		if (espeed>0){
			if ( espeed<20){
				zwarn("Target is running too slow");
				state_slow_warn=1;
			}
			else if (state_slow_warn){
				clear_warn();
				state_slow_warn=0;
			}
		}
	}else{

		sprintf(cs,">%lu/sec",total_exec);
	}

	last_exec_inq = total_exec;
	last_etime_inq = cur_timeus;

	return cs;

}
char *get_sig_name(int signum){
	int i;
	for (i=0;i<SIG_SET_SIZE;i++){
		if (signum==sig_set[i].id)
			return sig_set[i].name;
	}
	zwarn("Unknown crash signal from target: %d",signum);
	return "UNKNOWN";
}


char * psect(char *buf,int rlen,char *fmt, ...){
	char sbuf[255];
	int len;
	int i;

	buf[0]=0;
	sbuf[0] = 0;
	va_list argp;
	va_start(argp,fmt);
	vsprintf(buf,fmt,argp);
	va_end(argp);

	len = strlen(buf);
	if (len<rlen){
		for (i=0;i<(rlen-len);i++)
			strcat(sbuf," ");
		strcat(buf,sbuf);
	}else if(len>rlen){
		buf[len] = 0; //trim
	}
	return buf;

}

char * show_data(char *buf,void *orig_data,size_t len,size_t start,size_t end){
	size_t i;
	char line[255];
	char tmp[255];
	char *s;
	int finished =0 ;
	u8 extra;
	int len_limit = 128;
	u8 pad = 0;
	int page = (start/128);
	void *data = orig_data + (128*page);
	u8 mut_area=0;



	len = len - 128*page;
	if (len>len_limit) //still too much?
		len = len_limit;


	if (start==-1){
		zexit("Borad: Wrong arg START");
		start=0;
	}

	if (end <= start) {
		zexit("Board: Wrong args %lu %lu <%s>",start,end,cmt);
		start=0;
		end = 1;
	}


	if (start >= len_limit) start = start % len_limit;
	if (end >= len_limit) end = end % len_limit;


	if (len<=(len_limit-16)) pad=1;

	if (start >= len){
		zexit("Board: args overflow page offset %d %d %d",start,end,len);
	}

#define APPEND 	psect(tmp,78+extra,line);\
				strcpy(line,DStart VR DStop);\
				strcat(line,tmp);\
				strcat(line,DStart VR DStop);\
				strcat(buf,line);\
				if (finished) break;\
				strcat(buf,"\n");\

	strcpy(line,_15SP);
	s=&line[15];
	extra = 0;

	buf[0]=0;
	for (i=0;i<len_limit;i++){
		if (i==start && i%16!=15){
			strcpy(s,CRED);
			s+=7;
			extra+=7;
			mut_area=1;
		}
		if (i==end || i==len_limit-1){
			strcpy(s,CNORM);
			s+=4;
			extra+=4;
			mut_area=0;
		}

		if (i%16==0 && mut_area){
			strcpy(s,CRED);
			s+=7;
			extra+=7;
		}
		sprintf(s,"%02x",((unsigned char*)data)[i]);
		if (i==len-1){
			finished = 1;
			strcpy(s+2,CNORM);
			extra+=4;
			APPEND
		}

		if (i%16==15){
			if (i+1==len) finished=1;
			if (mut_area){
				strcpy(s+2,CNORM);
				extra+=4;
			}
			APPEND

			strcpy(line,_15SP);
			s=&line[15];
			extra = 0;
		}else{
			strcat(s," ");
			s+=3;
		}
	}

	if (pad){
		line[0]=0;
		extra=0;
		finished=0;
		strcat(buf,"\n");
		i = ((i/16)+1)*16;
		for (;i<len_limit;i++){
			if (i%16==15){
				if (i+1==len_limit) finished=1;
				APPEND
				line[0]=0;
			}
		}

	}
	return buf;
}


void refresh_board(void *data,size_t size,size_t start,size_t end){
	char buf[1024];
	char line[1024];
	char tmp[255];
	char line2[1024];
	char tmp2[255];
	char *sleft,*sright;
	int i,_is,_ie;
	static u8 cleared_once = 0;


	if (!use_term_gui) return;

	if (!cleared_once){
		printf(DC);
		cleared_once = 1;
	}


	printf(DH);
	printf("\n");
	SPACE(31) printf(CLGREEN"ZHARF <VERSION 1.1>\n");
	SPACE(32) printf("By Sirus Shahini\n"CNORM);





	printf(DStart LCD _32HO _6HO BHD BHD _32HO _6HO RCD DStop "\n" );


	printf(DStart VR DStop);

	i=strlen(target_path);
	if (strlen(target_path)<18)
		printf("%s",psect(buf,38+22,CDBlue"Target: "CNORM CYELLOW"%s"CNORM,target_path));
	else
		printf("%s",psect(buf,38+22,CDBlue"Target: "CNORM CYELLOW"%.8s...%s"CNORM,target_path,&target_path[i-10])); //%*s can be used to right align
	printf(DStart VR DStop);

	printf(DStart VR DStop);

	printf("%s",psect(buf,38+22,CDBlue"Last Independet: "CNORM CGRAY"%lu"CNORM,indp_counter));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	if (_st_bl)
		printf("%s",psect(buf,38+22,CDBlue"Blocks: "CNORM CGRAY"%lu"CNORM,_st_bl));
	else
		printf("%s",psect(buf,38+22,CDBlue"Blocks: "CNORM CGRAY"N/A"CNORM));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+22,CDBlue"Last Nested: "CNORM CGRAY"%lu"CNORM,nested_counter));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	if (_st_indp)
		printf("%s",psect(buf,38+22,CDBlue"Independent: "CNORM CGRAY"%lu"CNORM,_st_indp));
	else
		printf("%s",psect(buf,38+22,CDBlue"Independent: "CNORM CGRAY"N/A"CNORM));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	if (_st_indp)
		printf("%s",psect(buf,38+22,CDBlue"Coverage: "CNORM CGRAY"%lf"CNORM,(double)total_covered/_st_indp));
	else
		printf("%s",psect(buf,38+22,CDBlue"Coverage: "CNORM CGRAY"N/A"CNORM));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	if (_st_nes)
		printf("%s",psect(buf,38+22,CDBlue"Nested: "CNORM CGRAY"%lu"CNORM,_st_nes));
	else
		printf("%s",psect(buf,38+22,CDBlue"Nested: "CNORM CGRAY"N/A"CNORM));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+22,CDBlue"Time: "CNORM CGRAY"%s"CNORM,convert_time(tmp)));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart BVR _32HO _6HO DP DP _32HO _6HO BVL DStop "\n" );



	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Inputs: "CNORM"%d",input_count));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"TM OUT: "CNORM"%02d",(int)(active_timeout/1000)));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Queue Elms: "CNORM"%d",queue_ind));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38 + 22,CORANGE"Execs: "CNORM CWHITE"%lu"CNORM,total_exec));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"QI: "CNORM"%d",queue_use_ind));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Last Nodes: "CNORM"%lu",last_trace_nodes));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CLGREEN"Depth: "CNORM"%lu",max_depth));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Output: "CNORM"%s",output_dir));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"PModel: "CNORM"%s",pm_str));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Core: "CNORM"%d",attached_core));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Q coverage: "CNORM"%lf",((double)queue_use_ind)/queue_ind));
	printf(DStart VR DStop);

	printf(DStart VR DStop);
	printf("%s",psect(buf,38+11,CDBlue"Exec speed: "CNORM"%s",exec_speed(tmp)));
	printf(DStart VR DStop);

	printf("\n");


	printf(DStart BVR _32HO _6HO BHU BHU _32HO _6HO BVL DStop "\n" );

	printf(DStart VR DStop);
	printf("%s",psect(buf,78 + 18,CORANGE"Crashes: "CRED"%lu"CNORM,total_crashes));
	printf(DStart VR DStop);
	printf("\n");

	printf(DStart VR DStop);
	printf("%s",psect(buf,78 + 18,CORANGE"Unique Crashes: "CRED"%lu"CNORM,unique_crashes));
	printf(DStart VR DStop);
	printf("\n");

	printf(DStart VR DStop);
	if (save_soft_crash)
		printf("%s",psect(buf,78 + 18,CWHITE"Soft Crashes: "CORANGE"%lu "CNORM,soft_crashes));
	else
		printf("%s",psect(buf,78 + 18,CWHITE"Soft Crashes: "CORANGE"[DISABLED] "CNORM));
	printf(DStart VR DStop);
	printf("\n");

	printf(DStart VR DStop);
	if (save_soft_crash)
		printf("%s",psect(buf,78+18,CWHITE"Unique Soft Crashes: "CORANGE"%lu"CNORM,unique_soft_crashes));
	else
		printf("%s",psect(buf,78+18,CWHITE"Unique Soft Crashes: "CORANGE"[DISABLED]"CNORM));
	printf(DStart VR DStop);
	printf("\n");

	printf(DStart VR DStop);


	printf("%s",psect(buf,78 + 22,CWHITE"Fuzzer Status: "CNORM"%s",current_stat));

	printf(DStart VR DStop);

	printf("\n");



	printf(DStart BVR _64HO _14HO BVL DStop "\n" );

	printf(DStart VR DStop);
	strcpy(line,"Queue: ");
	strcpy(line2,"       ");
	if (queue_ind<10){
		_is = 0;
		_ie = 10;
	}else {
		_is = queue_use_ind-5;
		_ie = queue_use_ind+5;
	}
	if (_is<0)
		_is=0;
	if (_ie>queue_ind)
		_ie=queue_ind;

	for (i=_is;i<_ie;i++){
		if (i == queue_use_ind){
			sleft=CYELLOW;
			sright=CNORM;
		}else{
			sleft=0;
			sright=0;
		}
		if (input_queue[i].total_blocks<1000){
			sprintf(tmp2,"%s%03lu%s",(sleft?sleft:""),input_queue[i].total_blocks,(sright?sright:""));
			sprintf(tmp,"%s%03d%s",(sleft?sleft:""),input_queue[i].depth,(sright?sright:""));
		}else{
			sprintf(tmp2,"%s%lu%s",(sleft?sleft:""),input_queue[i].total_blocks,(sright?sright:""));
			sprintf(tmp,"%s%d%s",(sleft?sleft:""),input_queue[i].depth,(sright?sright:""));
		}
		if (input_queue[i].prio==0){
			strcat(tmp,"L,");
			strcat(tmp2,"L,");
		}
		else{
			strcat(tmp,",");
			strcat(tmp2,",");
		}

		strcat(line,tmp);
		strcat(line2,tmp2);
	}
	strcat(line," ...");


	printf("%s",psect(buf,78+11,line));
	printf(DStart VR DStop);
	printf("\n");

	printf(DStart VR DStop);
	printf("%s",psect(buf,78+11,line2));
	printf(DStart VR DStop);
	printf("\n");


	printf(DStart BVR _64HO _14HO BVL DStop "\n" );


	printf("%s",show_data(buf,data,size,start,end));
	printf("\n");


	printf(DStart BVR _64HO _14HO BVL DStop "\n" );

	printf(DStart VR DStop);
	printf("%s",psect(buf,78 + 11,stat_line));
	printf(DStart VR DStop);
	printf("\n");

	printf(DStart LCU _64HO _14HO RCU DStop "\n" );
	printf(DStop);

	printf("\n\n");


}

void print_usage(){
	printf("Usage: zharf -i <input_directory> -o <output_directory> <target_program>\n");
	printf("Arguments:\n"
			"\t i <path> : Directory of input seeds (Required)\n"
			"\t o <path> : Output directory (Required)\n"
			"\t f <path> : Input file to target\n"
			"\t n <port> : TCP mode\n"
			"\t m : Multithreaded targer\n"
			"\t c : Custom cleanup\n"
			"\t p: Pririty model (TNF, TDF, TNS)\n"
			"\t g: Limited; initial coverage only\n"
			"\t e: Limited; show initial basic block count\n"
			"\t a: Add coverage increasing inputs to the input directory\n"
			"\t k <n>: Performance check mode (0,1,2)\n"
			"\t r: Store graph (developer only)\n"
			"\t y <path>: Dictionary to use\n"
			"\t d: Debug mode (developer only)\n"
			"\t T <n>: Number of basic blocks (Get from zcc)\n"
			"\t N <n>: Number of nested blocks (Get from zcc)\n"
			"\t B: Number of independent basic blocks (Get from zcc)\n");

	exit(-1);
}


u8 check_adr(void *adr){
	return (adr >= shm_adr && adr <= shm_end);
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

#define ACQUIRE_LOCK while(!ulock((void *)lib_lock));
#define RELEASE_LOCK *lib_lock = 0;
#define ACQUIRE_LOCK_CONDITIONED	if (target_id) ACQUIRE_LOCK

#else

#define ACQUIRE_LOCK ;
#define RELEASE_LOCK ;
#define ACQUIRE_LOCK_CONDITIONED ;

#endif



void queue_add(char *file_path,u8 init){
	strcpy(input_queue[queue_ind].i_path,file_path);
	input_queue[queue_ind].initial = init;
	input_queue[queue_ind].prio = 1;
	input_queue[queue_ind].fixed_loc=0;
	input_queue[queue_ind].marked = 0;
	input_queue[queue_ind].passed = 0;
	input_queue[queue_ind].leaves = 0;

	queue_ind++;
	if (queue_ind == INPUT_MAX){
		queue_ind=0;
	}

}


/*
	Implementation of new priority models goes here
*/
u8 queue_add_traced(struct input_val *iv, int *add_indx){
	struct input_val *cur;
	struct input_val temp;
	u8 swap;


#define CHECK_QUEUE_CAP		if (queue_ind == queue_use_ind){\
								zwarn("Hit queue slider. Discarding tail.");\
								queue_ind = 0;\
								queue_hit_sl = 1;\
							}


#define LP_PROB_FIX	(!RU8(5))


	queue_hit_sl = 0;

	switch (pm_mode){
		case 0:

			if (iv->prio == 0){
				if (iv->depth < LPSD_MAX_DEPTH){
					if (LPSD_queue[iv->depth] > MLPSD_ALLOWED){

						return 0;
					}
					LPSD_queue[iv->depth]++;
				}

			}

			CHECK_QUEUE_CAP

			cur=&input_queue[queue_ind];
			*cur=*iv;

			if (cur->prio == 1 || (cur->prio ==0 && sort_low_prio)){

				while (cur != input_queue){

					swap=0;



					if ((cur-1)->initial){
						break;
					}
					if (queue_use_ind + 1 == (u64)(cur-input_queue) )
					{
						break;
					}

					if (cur->prio==0 && (cur-1)->fixed_loc){
						break;
					}


					if (cur->prio < (cur-1)->prio){
						break;
					}else if (cur->prio > (cur-1)->prio){
						swap=1;

					}else{
						if (!cur->marked && (cur-1)->marked){
							break;
						}else if (cur->marked && !(cur-1)->marked){
							swap=1;
						}else if (!target_mult_threaded && cur->depth>(cur-1)->depth){
							swap=1;
						}else if (cur->depth == (cur-1)->depth){
							if(cur->total_blocks > (cur-1)->total_blocks){
								swap=1;
							}else if(cur->total_blocks == (cur-1)->total_blocks){
								if(cur->total_hits > (cur-1)->total_hits){
									swap=1;
								}else{
									break;
								}
							}
							else{
								break;
							}
						}else{
							break;
						}
					}
					if (swap){
						temp=*cur;
						*cur=*(cur-1);
						*(cur -1)=temp;
						cur--;
					}

				}
			}

			break;

		case 1:
			if (iv->prio == 0){
				if (iv->total_blocks < LPSC_MAX_NODES){
					if (LPSC_queue[iv->total_blocks] > MLPSC_ALLOWED){
						return 0;
					}
					LPSC_queue[iv->total_blocks]++;
				}
			}


			CHECK_QUEUE_CAP

			cur=&input_queue[queue_ind];
			*cur=*iv;

			if (cur->prio == 1 || (cur->prio ==0 && sort_low_prio)){

				while (cur != input_queue){
					swap=0;
					if ((cur-1)->initial){
						break;
					}
					if (queue_use_ind + 1 == (u64)(cur-input_queue) )
					{
						break;
					}

					if (cur->prio==0 && (cur-1)->fixed_loc){
						break;
					}

					if (cur->prio < (cur-1)->prio){
						break;
					}else if (cur->prio > (cur-1)->prio){
						swap=1;

					}else{
						if (!cur->marked && (cur-1)->marked){
							break;
						}else if (cur->marked && !(cur-1)->marked){
							swap=1;
						}else if (cur->total_blocks>(cur-1)->total_blocks){
							swap=1;
						}else if (cur->total_blocks == (cur-1)->total_blocks){
							if(cur->depth > (cur-1)->depth){
								swap=1;
							}else if(cur->depth == (cur-1)->depth){
								if(cur->total_hits > (cur-1)->total_hits){
									swap=1;
								}else{
									break;
								}
							}
							else{
								break;
							}
						}else{
							break;
						}
					}
					if (swap){
						temp=*cur;
						*cur=*(cur-1);
						*(cur -1)=temp;
						cur--;
					}

				}
			}
			break;
		case 2:
			cur=&input_queue[queue_ind];
			*cur=*iv;
			break;
		default:
			zexit("Undefined mode");

	}

	cur->initial = 0;


	if (cur->prio ==0 && lpq_balance==0){
		if (LP_PROB_FIX){
			cur->fixed_loc=1;
		}
	}

	queue_ind++;
	if (queue_ind == INPUT_MAX){
		queue_ind=0;
	}

	*add_indx = (int)(cur-input_queue);

	return 1;
}

void block_add_traced(struct block_info_local *b){
	struct block_info_local *cur;
	struct block_info_local temp;

	total_covered++;
	cur=&sorted_blocks[++block_ind];
	*cur=*b;
	while (cur != sorted_blocks){
		if (cur->id<(cur-1)->id){
			temp=*cur;
			*cur=*(cur-1);
			*(cur -1)=temp;
		}else{
			break;
		}
		cur--;
	}

}

u8 check_block(struct block_info_local *b){
	long low=0,high=block_ind,mid;
	while (low<=high){
		mid=(high+low)/2;
		if (b->id==sorted_blocks[mid].id){

			if (sorted_blocks[mid].hits >= b->hits){

				return 3;
			}else{
				sorted_blocks[mid].hits =b->hits;
				return 1;
			}
		}else if(b->id>sorted_blocks[mid].id){
			low = mid+1;
		}else{
			high = mid-1;
		}
	}
	return 2;
}
int next_queue_ind(){
	if (queue_use_ind+1 == queue_ind){
		queue_use_ind=-1;
	}
	return ++queue_use_ind;
}
void prepare_file_feed(char *base_input){
	char cmd[2048];
	sprintf(cmd,"cp %s %s",base_input,feed_file_path);
	system(cmd);
}

void prepare_input_feed(){
	if (file_feed){

		prepare_file_feed(input_queue[0].i_path);

	}else{
		feed_fd = open(CURRENT_INPUT,O_RDWR | O_CREAT /*| O_EXCL*/,0600);
		if (feed_fd<0){
			printf("%s\n",strerror(errno));
			zexit("Can't create input file");
		}
	}
}
void run_starter(){

	char buf;
	int n;

	/*
		Create shared memory
	*/
	shm_id = shmget(IPC_PRIVATE,SHM_SIZE,IPC_CREAT | IPC_EXCL | 0600);
	if (shm_id<0){
		zexit("Can't create shared memory");
	}
	shm_adr = shmat(shm_id,0,0);

	if (shm_adr==(void*)-1){
		zexit("Can't attach to shared memory.");
	}
	memset(shm_adr,0,SHM_SIZE);
	shm_end = shm_adr+SHM_SIZE;

	/*
		Set lock
		This will not change
	*/
	lib_lock = shm_adr;

	pipe(cmd_send);
	pipe(response_recv);

	starter_id = fork();
	if (!starter_id){

		/*
			I'm starter
			Establish communication channel
		*/
		dup2(cmd_send[0],FD_IN);
		dup2(response_recv[1],FD_OUT);
		close(cmd_send[1]);
		close(response_recv[0]);
		close(cmd_send[0]);
		close(response_recv[1]);

		if (file_feed){
			close(0);
			/*
				We expect the user to have correctly written
				the input filename as the argument to the target
				It has to be the same as -f for zharf

				NOTE: There are cases that in this mode
				target still prompts for user input
				and since stdin is closed, it will fail
				If it keeps trying, it will eventually timeout.
			*/
		}else{
			dup2(feed_fd,0);
			close(feed_fd);
		}
		dup2(dev_null,1);
		dup2(dev_null,2);

		close(dev_null);

		/*
			In case libzh.so is not installed
			system-wide.
			In that case we assume the user is
			running the fuzzer from the directory
			that libzh and zharf reside.
		*/
		setenv("LD_LIBRARY_PATH",".",1);

		execv(target_path,target_argv);
		n=open("/dev/tty",O_WRONLY);
		if (n!=1){
			dup2(n,1);
			close(n);
		}
		zexit("Running starter (%s) failed. %s",target_argv[0],strerror(errno));

	}

	close(cmd_send[0]);
	close(response_recv[1]);
	n=write(cmd_send[1],&shm_id,4);
	if (n<1){
		zexit("Can't write to starter");
	}

	n=write(cmd_send[1],&shm_adr,8);
	if (n<1){
		zexit("Can't write to starter");
	}

	/*
		Wait for answer
	*/
	zrep("Waiting for starter...");
	n=read(response_recv[0],&buf,1);
	if (n<1){
		zexit("Can't read response from starter");
	}
	/*
		Starter is ready to receive
		fork command. We're done here
	*/

	zrep("Starter ready");

}
void read_inputs(){
	/*
		Read all inputs
		add them to the queue
	*/
	struct dirent **entry_list;
	int ent_count;
	int i;
	struct stat st;


	ent_count = scandir(input_dir,&entry_list,0,alphasort);

	for (i=0;i<ent_count;i++){
		char *ent_name;
		char ent_path[MAX_PATH];

		ent_name = 	entry_list[i]->d_name;
		if (strcmp(ent_name,".")==0 || strcmp(ent_name,"..")==0) continue;

		strcpy(ent_path,input_dir);
		if (input_dir[strlen(input_dir)-1]!='/')
			strcat(ent_path,"/");
		strcat(ent_path,ent_name);
		if (lstat(ent_path,&st)<0){
			printf("%s\n",strerror(errno));
			zexit("stat failed");
		}

		if(!S_ISDIR(st.st_mode)){
			if (st.st_size < MIN_INPUT_SIZE || st.st_size > MAX_INPUT_SIZE){
				zexit("Input '%s' violates default size limit",ent_path);
			}
			queue_add(ent_path,1);
			free(entry_list[i]);
			input_count++;
		}
	}
	if (entry_list)
		free(entry_list);

}


void modify_input(char *input_base){
	char c;
	int new_input_len=0;
	int fd;
	int n;


	lseek(feed_fd,0,SEEK_SET);
	fd = open(input_base,O_RDONLY);
	while (read(fd,&c,1)){
		n=write(feed_fd,&c,1);
		new_input_len++;
		if (n<1){
			zexit("can't modify current input");
		}
	}
	close(fd);
	if (ftruncate(feed_fd,new_input_len))
		zexit("can't truncate current input");

	lseek(feed_fd,0,SEEK_SET);


}
void start_timer(){
	struct itimerval itimer;

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = 0;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = active_timeout;

	setitimer(ITIMER_REAL,&itimer,0);

	target_timedout = 0;

}
void stop_timer(){
	struct itimerval itimer;

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = 0;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL,&itimer,0);

}
/*
	When this function is called
	target is either dead or will be killed here
*/
int do_term_check(){
	int n;
	int exit_status;
	int sig_val;


	start_timer();

	n = read(RIN, &exit_status, 4);

	if (n<4){
		zexit("Read exit status failed");
	}
	/*
		Do these two lines fast
	*/
	target_id = 0;
	stop_timer();

	RELEASE_LOCK

	debug_exit_stat = exit_status;

	/*
		Why did it exit?
	*/
	if (WIFEXITED(exit_status)){
		return TRG_EX_NORMAL;
	}
	if (WIFSIGNALED(exit_status)){
		sig_val = WTERMSIG(exit_status);

		if (target_timedout && sig_val==SIGKILL){
			return TRG_EX_TMOUT;
		}
		/*
			In network mode we're usually not
			interested in PIPE signal.
			User is free to remove this condition
			if that's a concern.
		*/
		if (sig_val==SIGPIPE){
			return TRG_EX_NORMAL;
		}

		last_crash_sig = sig_val;
		return TRG_EX_CRASH;
	}

	return -1;
}
void set_recv_timeout(struct timeval * t){
    if (setsockopt(net_sock,SOL_SOCKET,SO_RCVTIMEO,(char *)t,sizeof(struct timeval))<0){
        zexit("setsockopt failed\n");
    }
}
void init_socket(){
	struct timeval twait;

	/*
		Currently it's assumed the connection is TCP
	*/
	if (net_sock>0)
		close(net_sock);
	net_sock = socket(AF_INET,SOCK_STREAM,0);
	if (net_sock<1){
		zexit("socket() failed %s",strerror(errno));
	}
	twait.tv_sec = 0;
	twait.tv_usec =RECV_WAIT;
	set_recv_timeout(&twait);
}
int reconnect(){
	init_socket();
	if (connect(net_sock,(struct sockaddr*)&target_saddr,sizeof(target_saddr)))
		return 0;
	return 1;
}

void reset_structures(){
	/*
		Reset everything for the new execution
		including clearing the shared memory
		In net mode this will make the initialization
		parts of the target disappear from the
		output graph if saved.
	*/
	dl_index=-1;
	graph_e_count=0;

	ACQUIRE_LOCK_CONDITIONED

	memset(shm_adr+LOCK_DELTA,0,SHM_SIZE-LOCK_DELTA);
	RELEASE_LOCK

	nested_counter=0;
	indp_counter=0;
	skip_nodes=0;
}

/*
	Some programs may need cleanup before
	execution. This may be necessary because
	termination of the program due to timeout
	might have deprived it from carrying out
	its clean up stage!
	We accept user-defined terminal commands here
	to be run for this purpose.

	Users must be careful what commands
	are passed to zharf.
*/
void custom_cleanup(){
	int i;

	for (i=0;i<sizeof(cleanup_cmds)/8;i++){
		system(cleanup_cmds[i]);
	}

}
/*
	Spawn a new instance of the target

	init_run: only used in net mode
*/
int execute(int init_run){
	int n;
	int res;
	u8 con_waits =0 ;

	reset_structures();

	if (enable_custom_cleanup)
		custom_cleanup();

	write(COUT,".",1);

	n=read(RIN,&target_id,4);

	if (n<4){
		zexit("target execution failed");
	}



	if (init_run || !net_mode){
		res = do_term_check();
		if (res!=-1)
			return res;
	}else{
		/*
			In network mode we don't restart the target
			for each input.
			We send inputs until it crashes and fails to
			send a response back.
			If that happens, only then we read the return status
			wait until target gets its stuff together and
			establish the connection.
		*/
		while (1){
			usleep(CONNECT_WAIT);
			init_socket();

			con_waits++;
			if (connect(net_sock,(struct sockaddr*)&target_saddr,sizeof(target_saddr))){
				if (con_waits==CONN_MAX_RETRIES){
					do_term_check();
					zexit("Target doesn't respond to new connections.");
				}
			}else{

				break;
			}
		}
		return TRG_NET_MODE;
	}
	/*
		If we are here then it's an unexpected
		state and must be further investigated
	*/
	return -1;
}
void target_timeout(int signal){

	if (target_id>0){
		target_timedout = 1;
		//zrep("Target %d timed out",target_id);
		/*
			Kill target and all its forks
			If target has created a new process group
			then we can simply kill all by passing -pid
			to kill.
			But since this is not necessarily the case
			we can recursively search for all of them
			using pgrep.
			This solution solution is too slow and
			reading and scanning proc is also slow
			We can't afford this.
			Instead, forget about getting the lock
			after this this function. This way fuzzer
			won't get stuck for a locked shm.
			This is done by ACQUIRE_LOCK_CONDITIONED
			In this case if shm is locked by children
			which may have crashed in lib tree will be discarded
			which is okay since the tree is probably
			corrupted anyways.
		*/

		if(kill(target_id,SIGKILL)){
			if (errno!=3)
				zexit("kill(): %s",strerror(errno));
		}
		target_id=0;
	}
}
/*
	This saves the whole shared memory
	for debugging
*/
void save_memory(char *dir_path,char *stage){
	char fname[255];
	FILE *f;
	u64 n;

	if (debug_mode)
		return;

	sprintf(fname,"%s/shared_mem_%016lx_%s",dir_path,(u64)shm_adr,stage);

	f=fopen(fname,"w");
	if (!f){
		zexit("save_mem: Can't open file\n");
		return;
	}

	if ((n=fwrite(shm_adr,1,SHM_SIZE,f))<SHM_SIZE){
		printf("Incomplete memory save %lu\n",n);
	}
	fclose(f);

	zrep("Memroy saved in %s",fname);
	output_count++;
}

void record(void *data,size_t size){
	FILE *f;
	char file_path[255];
	char tmp[128];

	strcpy(file_path,"tmp/");
	sprintf(tmp,"inp%lu",debug_rec_ind++);
	strcat(file_path,tmp);
	if (access("tmp",F_OK)){
		if (mkdir("tmp",0775)){
			printf("%s\n",strerror(errno));
			zexit("mkdir: record (tmp)");
		}
	}

	f=fopen(file_path,"w");
	if (!f){
		zexit("fopen(): record");
	}
	if (fwrite(data,1,size,f)<size){
		zwarn("fwrite(): record");
	}
	fclose(f);
}

void store_reset(u8 store){
	char dir_path[255];
	char tmp[128];
	char cmd[1024];
	u64 i;

	if (store){
		strcpy(dir_path,"debug/");
		sprintf(tmp,"crash%lu",debug_rec_dir);
		strcat(dir_path,tmp);

		if (access(dir_path,F_OK)){
			if (mkdir(dir_path,0775)){
				printf("%s\n",strerror(errno));
				zexit("mkdir: store_reset (%s)",dir_path);
			}
		}

		for (i=0;i<debug_rec_ind;i++){
			sprintf(cmd,"cp tmp/inp%lu debug/crash%lu/",i,debug_rec_dir);
			system(cmd);
		}
		debug_rec_dir++;
	}
	debug_rec_ind = 0;

}
void znormal_exit(){
	terminate_units();
	zrep("Exiting normally");
	rep_use_time();
	exit(0);
}
void int_handler(int signal){
	znormal_exit();
}
void pipe_handler(int signal){
	zexit("Received SIGPIPE, forkserver down?");
}

void rep_adrs(){
	printf("\n\nSHM: start %016lx end %016lx\n",(u64)shm_adr,(u64)(shm_adr+SHM_SIZE));
	printf("Root node: %016lx\n",(u64)shared_trace_tree->root);
	printf("Corrupted node: %016lx\n",(u64)_debug_node);
	printf("Corrupted node's child list: %016lx\n",(u64)_debug_node->children);
	if (_debug_node->children)
		printf("Corrupted node child node: %016lx\n",(u64)(_debug_node->children)->child_node);
	zrep("HITS: %lu, Tree Nodes: %lu",shared_trace_tree->total_hits,shared_trace_tree->count);
}
void show_maps(){
	char cmd[255];
	int c;
	FILE *f;
	char buf[8192];
	int index=0;

	memset(buf,0,8192);
	sprintf(cmd,"cat /proc/%d/maps",getpid());
	f = popen(cmd,"r");

	while ((c=fgetc(f))!=EOF){
		buf[index++] = c;
	}

	pclose(f);

	printf("\nMemory mappings: \n%s",buf);
}

void sigf_handler(int signum, siginfo_t *si, void *ucontext){
	void *buf[100];
	int n;
	char **names;
	int i;

	signal(SIGSEGV,SIG_DFL);

	n=backtrace(buf,100);
	names=backtrace_symbols(buf,n);



	printf("\n\n*************** " CRED "FATAL STATE " CNORM "***************\n");
	for (i=0;i<n;i++){
		printf("> %s\n",names[i]);
	}
	printf("Address fault: %016lx\n",(u64)si->si_addr);
	//rep_adrs();

	show_maps();

	zexit("Exiting due to segmentation fault");
}
void dfs_add(ID_SIZE id){
	ID_SIZE *cur;
	ID_SIZE temp;
	cur=&dfs_list[++dl_index];

	*cur=id;

	while (cur != dfs_list){
		if (*cur<*(cur-1)){
			temp=*cur;
			*cur=*(cur-1);
			*(cur -1)=temp;
		}else{
			break;
		}
		cur--;
	}

}

u8 visited(ID_SIZE id){
	long low=0,high=dl_index,mid;
	while (low<=high){
		mid=(high+low)/2;
		if (id==dfs_list[mid]){
			return 1;
		}else if(id > dfs_list[mid]){
			low = mid+1;
		}else{
			high = mid-1;
		}
	}
	return 0;
}
void save_netdata(void *data,u64 size,char *file_path){
	FILE *nets ;
	char fp[255];
	char tmp[16];

	strcpy(fp,file_path);
	sprintf(tmp,"%d",save_net_i++);
	strcat(fp,tmp);
	nets = fopen(fp,"w");
	if (!nets){
		zexit("save net");
	}
	fwrite(data,size,1,nets);
	fclose(nets);

}
void save_debug_info(){
	static int debug_index = 0;
	FILE *f;
	char dir_path[255];
	char file_path[255];
	char tmp[128];
	char content[1024];

	strcpy(dir_path,"debug/");
	sprintf(tmp,"debug%d",debug_index++);
	strcat(dir_path,tmp);
	if (access("debug",F_OK)){
		if (mkdir("debug",0775)){
			printf("%s\n",strerror(errno));
			zexit("mkdir: save_debug_info (debug)");
		}
	}
	if (access(dir_path,F_OK)){
		if (mkdir(dir_path,0775)){
			printf("%s\n",strerror(errno));
			zexit("mkdir: save_debug_info (%s)",dir_path);
		}
	}
	strcpy(file_path,dir_path);
	strcat(file_path,"/");
	strcat(file_path,"info");

	f=fopen(file_path,"w");
	if (!f){
		printf("%s , %s\n",strerror(errno),file_path);
		zexit("open(): save_debug_info");
	}

	strcpy(content,"Exit reason: ");
	switch (debug_exit_code){
		case TRG_EX_NORMAL:
			strcat(content,"normal exit\n");
			break;
		case TRG_EX_TMOUT:
			strcat(content,"timeout\n");
			break;
		case TRG_EX_CRASH:
			strcat(content,"crash\n");
			break;
		case TRG_NET_MODE:
			strcat(content,"Traget is alive\n");
			break;
		default:
			sprintf(tmp,"Unknown: %d %08x\n",debug_exit_code,debug_exit_stat);
			strcat(content,tmp);
	}
	strcat(content,"Elapsed time: ");
	strcat(content,convert_time(tmp));
	strcat(content,"\n");
	fwrite(content,1,strlen(content),f);
	fclose(f);

	strcpy(file_path,dir_path);
	strcat(file_path,"/");
	strcat(file_path,"input");

	save_netdata(debug_data,debug_data_size,file_path);

	if (should_save_mem){
		save_memory(dir_path,"debug");
	}
	rep_adrs();


}
#define get_node_type(info_byte)	(info_byte & BLOCK_TYPE)
#define get_node_mark(info_byte)	(info_byte & BLOCK_MARKED)


int dfs(struct node *n,FILE *graph_file){
	char line[255];
	int node_depth=0;
	char label[2];
	char color[10];
	ID_SIZE _pid;


	if (!check_adr(n)){
		has_corrupted_shm=1;
		return 0;
	}
	_debug_node=n;

	if (visited(n->id)){
		return 0;
	}

	dfs_add(n->id);


	if (get_node_type(n->info)==0){
		strcpy(color,"red");
		label[0]='I';
		indp_counter++;
	}else{
		strcpy(color,"orange");
		label[0]='N'; //nested
		nested_counter++;
	}

	if (get_node_mark(n->info)){
		marked_tree = 1;
	}

	if (n->children){
		struct child_ptr *c;
		struct node *temp;

		c=n->children;
		if (!check_adr(c)){
			has_corrupted_shm=1;
			return 0;
		}
		label[1]=0;
		_pid = n->id;

		last_trace_leaves--;
		//printf("%lu\n",n->id);
		while (c){
			int branch_depth;

			last_trace_leaves++;
			if (should_store_graph){
				ID_SIZE _cid;

				if (skip_nodes<SHOULD_SKIP_COUNT){
					skip_nodes++;
					goto graph_end;
				}

				if (!check_adr(c->child_node) ){
					has_corrupted_shm=1;
					return 0;
				}

				_cid=(c->child_node)->id;

				if (graph_e_count<MAX_EDGES_VISIBLE){
					sprintf(line,"\"0x%016lx\" [color=%s, label=\"%s\" penwidth=3.0]\n"
								 "\"0x%016lx\" [color=green, label=\"L\"]\n"
								 "\"0x%016lx\"->\"0x%016lx\" [color=white]\n"
									,_pid,color,label,_cid,_pid,_cid);

					if(fwrite(line,1,strlen(line),graph_file) < strlen(line)){
						zexit("fwrite(): build graph");
					}
					graph_e_count++;
				}
			}
graph_end:
			if (!check_adr(c->child_node) ){
				has_corrupted_shm=1;
				return 0;
			}
			temp = c->child_node;
			branch_depth = dfs(temp,graph_file);
			if (branch_depth > node_depth){
				node_depth = branch_depth;
			}

			c=c->next_child;
		}

	}else{

	}

	return node_depth+1;

}

int coverage_changes(){
	u8 changed=0;
	struct block_info *b = (struct block_info *) (shm_adr + 256);
	struct block_info_local temp_block;


	if(!check_adr(b)){
		return -1;
	}
	while(b->id){

		u8 r;
		temp_block.id = b->id;

		if (!check_adr(b->ptr)){
			return -1;
		}
		temp_block.hits = (b->ptr)->hits;
		r=check_block(&temp_block);
		if (r==1){
			/*
				existing block with
				new hit
				check_block has updated the hit

				Starvation hazard
				The problem with storing a new input only
				because it has a bigger hit number can
				result in consequentive similar inputs
				which starves other inputs in the queue.
				To resolve this issue I decrease the priority of such
				inputs
			*/
			if (!changed) changed = 2;
		}else if(r==2){
			block_add_traced(&temp_block);
			changed = 1;
		}
		b++;

	}


	if (depth_grew){
		changed=1;
	}

	return changed;

}

void vars(u64 blocks_count,u64 children_count,u64 linear_size,u64 nodes_size,u64 children_size,u64 total_extract_size){
	printf(" >> %lu %lu %lu %lu %lu %016lx\n",
	blocks_count,children_count,linear_size,nodes_size,children_size,total_extract_size);
}
/*
	Returns a pointer to a temporary memory
	containing the extracted map to hash
*/
void *extract_map(u64 *size){
	/*
		top 1/4 for linear blocks
		middle 2/4 for node_pool
		bottom 1/4 for child_pool
	*/
	struct block_info * blocks= (struct block_info *) (shm_adr + 256);
	struct node * node_pool = (struct node *)(shm_adr+(u64)(SHM_SIZE>>2));
	struct child_ptr* child_pool = (struct child_ptr*)(shm_adr+(u64)(3*(SHM_SIZE>>2)));
	u64 blocks_count ;
	u64 children_count;
	u64 linear_size;
	u64 nodes_size;
	u64 children_size;
	u64 total_extract_size;
	void *tmp_map;

	blocks_count = shared_trace_tree->count;
	children_count = shared_trace_tree->total_children;

	linear_size = blocks_count*sizeof(struct block_info);
	nodes_size = blocks_count*sizeof(struct node);
	children_size = children_count*sizeof(struct child_ptr);

	total_extract_size = 256 + linear_size + nodes_size + children_size;
	//vars(blocks_count,children_count,linear_size,nodes_size,children_size,total_extract_size);
	if (total_extract_size > SHM_SIZE){
		zexit("Extract size %016lx exceeds map size %016lx",total_extract_size,SHM_SIZE);
	}
	tmp_map= mmap(0,total_extract_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);

	if (tmp_map==MAP_FAILED){
		zexit("extract_map: mmap");
	}

	memcpy(tmp_map,shm_adr,256);
	memcpy(tmp_map + 256,(void *)blocks,linear_size);
	memcpy(tmp_map + 256 + linear_size,(void *)node_pool,nodes_size);

	memcpy(tmp_map + 256 + linear_size + nodes_size,(void *)child_pool,children_size);

	*size = total_extract_size;
	return tmp_map;
}
/*
	Our shared memory is huge. For most programs
	only a small part of the shm is used. We
	want to extract the used part and hash it
*/
u32 do_hash(){
	void *tmp_adr;
	u64 size;
	u32 hash;

	tmp_adr=extract_map(&size);
	hash = hashmap(tmp_adr,size,HASH_SEED);

	//release memory
	if (munmap(tmp_adr,size)){
		zexit("do_hash() - munmap");
	}

	return hash;
}
/*
	When a currption in the tree is detected we
	don't decide about what to do with the target
	and we'll leave that decision to the generator
	In the case of tree corruptoin the targrt
	might already be dead or still running in net mode
*/
void eval_tree(struct input_val *iv){
	FILE *graph_file;
	char gname[1064];
	char g_head[]="digraph trace{\n"
				"graph [bgcolor=black]\n"
				"labelloc=t\n"
				"fontcolor=white\n"
				"label= \"\\n\"\n"
				"node [color=red "
				"fontcolor=white fillcolor=black style=filled]\n";
	char g_tail[] ="}\n";

	depth_grew = 0;
	invd_tree_nodes_grew = 0;
	last_trace_leaves = 1; //1 for root
	marked_tree = 0;

	if (!check_adr(shared_trace_tree->root)){
		/*
			We use this to catch premature death
			So we don't set has_corrupted_shm
		*/
		iv->depth = 0;
		return ;
	}
	if (debug_mode)
		zrep("HITS: %lu, Tree Nodes: %lu",shared_trace_tree->total_hits,shared_trace_tree->count);


	/*
		Graph building
	*/
	if (should_store_graph){

		sprintf(gname,"%s/graph%d.dot",output_dir,(gcount % GRAPH_FILES_COUNT));
		//sprintf(cmd,"dot -Tpng -o %s/graph%d.png %s/graph%d.dot",output_dir,(gcount % GRAPH_FILES_COUNT)
		//																  ,output_dir,(gcount % GRAPH_FILES_COUNT));

		gcount++;
		graph_file=fopen(gname,"w");
		if (!graph_file){
			printf("%s\n",strerror(errno));
			zexit("fopen(): graph: %s",gname);
		}
		fwrite(g_head,strlen(g_head),1,graph_file);


		shared_trace_tree->depth=dfs(shared_trace_tree->root,graph_file);
		fwrite(g_tail,strlen(g_tail),1,graph_file);
		fclose(graph_file);

	}else{
		shared_trace_tree->depth=dfs(shared_trace_tree->root,0);
	}

	if (debug_mode)
			zrep("Tree Depth: %d\n",shared_trace_tree->depth);

	/*
		Set iv
	*/
	if (shared_trace_tree->depth < 1){
		//zwarn("Invalid depth in trace tree");
	}

	iv->depth = shared_trace_tree->depth;
	if (iv->depth > max_depth){
		max_depth = iv->depth;
		depth_grew = 1;

	}

	iv->total_blocks=shared_trace_tree->count;
	if (iv->total_blocks > max_coverage_tree_nodes){
		max_coverage_tree_nodes = iv->total_blocks;
		invd_tree_nodes_grew = 1;
	}
	iv->total_hits=shared_trace_tree->total_hits;
	iv->leaves = last_trace_leaves;

	if (need_csum){
		iv->hash = do_hash();
		current_csum = iv->hash;
	}
	total_target_hits+=shared_trace_tree->total_hits;
	last_trace_nodes=shared_trace_tree->count;

}
/*
	debug and exit
*/
void debug_memory(void *adr){
	char fname[255];
	FILE *f;

	sprintf(fname,"tmp/shared_mem_%016lx",(u64)adr);
	printf("Openning %s\n",fname);
	f=fopen(fname,"r");
	struct input_val tmp;

	if (!f){
		printf("Can't load memory\n");
		return;
	}

	shm_adr = mmap(adr,SHM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);
	shm_end = shm_adr + SHM_SIZE;
	if (shm_adr==MAP_FAILED){
		zexit("Can't allocate memory");
		return;
	}
	if (shm_adr != adr){
		zexit("Couldn't load memory where it should be");
	}
	shared_trace_tree = shm_adr + LOCK_DELTA + PROT_VARS_DELTA;

	if (fread(shm_adr,1,SHM_SIZE,f)<SHM_SIZE){
		zexit("Incomplete memory read");
	}
	fclose(f);

	eval_tree(&tmp);
	zrep("eval complete");

	if (munmap(shm_adr,SHM_SIZE)){
		zexit("debug_memory: munmap()");
	}
}



/*
	Check whether this mutation could already been
	produced my bitflip phase
	Idea from AFL
*/
u8 bitflip_check(u32 val_diff){
	u8 shift_count=0;

	if (!val_diff) return 0;

	while((val_diff & 1) !=1){
		val_diff>>=1;
		shift_count++;
	}

	if (val_diff==3 || val_diff==5 || val_diff==15){
		return 1;
	}

	if (shift_count & 7) return 0;

	if (val_diff == 0xff || val_diff==0xffff || val_diff==0xffffffff){
		return 1;
	}

	return 0;
}
u8 check_interesting(size_t byte_index,int value){
	u8 *loc8;
	u16 *loc16;
	u8 *i_adr = (u8 *)&value;
	int i=0,j=0;

	for (i=0;i<4;i++){
		if (!mut_map[byte_index+i]) continue;
		loc8 = i_adr + i;
		for (j=0;j<sizeof(set_8_ints);j++){
			/*
				Be careful not to compare signed and unsigned
				entities since the compiler might behave
				agaist what you expect
			*/
			if (((u8)set_8_ints[j]) == *loc8){
				return 1;
			}
		}
	}


	for (i=0;i<3;i++){
		if (!mut_map[byte_index+i] && !mut_map[byte_index+i+1]) continue;
		loc16 = (u16*)(i_adr + i);
		for (j=0;j<sizeof(set_16_ints);j++){
			if (((u16)set_16_ints[j]) == *loc16){
				return 1;
			}
		}
	}


	if (!mut_map[byte_index]  && !mut_map[byte_index+i+1]
		 && !mut_map[byte_index+i+2]  && !mut_map[byte_index+i+3]) return 0;

	for (j=0;j<sizeof(set_32_ints);j++){
		if (set_32_ints[j] == value){
			return 1;
		}
	}

	return 0;
}
/*********** Mutation functions ****************/

#define FLIP(start_adr,bit_n)	do{\
									u8 *st  = (u8 *)start_adr;\
									u64 bn  = (u64)bit_n;\
									st[(bn)/8] ^= (1 << (7 & bn));\
								}while(0)

#define REPMUT(cmt) zrep("Current mut technique: %s",cmt)
/*
	param start: report back where mutation started

*/
u8 bit_flip(void *data,size_t size,u8 op,size_t *start){
	/*
		This variable is bit number
		0 ... size*8-1
	*/
	static size_t bit_flip_index=0;
	u8 ignore =0 ;

bit_flip_start:


	*start = bit_flip_index >> 3;

	if (bit_flip_index > (size<<3)){
		zexit("FLIP1: index out of range");
	}

	if (!mut_map[*start]){
		ignore = 1;

		*start=-1;

	}else{
		FLIP(data,bit_flip_index);
	}

	cmt = "[MUT-B-F-1]";

	if (!bit_flip_index) REPMUT(cmt);

	bit_flip_index++;


	if (bit_flip_index==size*8){
		bit_flip_index=0;
		return op+1;
	}

	if (ignore){
		ignore = 0;
		goto bit_flip_start;
	}

	return op;
}

u8 bit2_flip(void *data,size_t size,u8 op,size_t *start){
	static size_t bit_flip_index=0;
	u8 ignore = 0;

bit2_flip_start:

	*start = bit_flip_index >> 3;

	if (bit_flip_index > (size<<3)-1){
		zexit("FLIP2: index out of range");
	}

	if (!mut_map[*start] /*&& !mut_map[((bit_flip_index+1) >> 3)]*/){
		ignore = 1;

		*start=-1;

	}else{
		FLIP(data,bit_flip_index);
		FLIP(data,bit_flip_index+1);
	}
	cmt = "[MUT-B-F-2]";
	if (!bit_flip_index) REPMUT(cmt);
	bit_flip_index++;


	if (bit_flip_index==size*8 - 1){
		bit_flip_index=0;
		return op+1;
	}

	if (ignore){
		ignore = 0;
		goto bit2_flip_start;
	}

	return op;
}

u8 bit4_flip(void *data,size_t size,u8 op,size_t *start){
	static size_t bit_flip_index=0;
	u8 ignore = 0;

bit4_flip_start:

	*start = bit_flip_index >> 3;

	if (bit_flip_index > (size<<3)-3){
		zexit("FLIP4: index out of range");
	}

	if (!mut_map[*start] /*&& !mut_map[((bit_flip_index+3) >> 3)]*/){
		ignore = 1;
		*start=-1;
	}else{
		FLIP(data,bit_flip_index);
		FLIP(data,bit_flip_index+1);
		FLIP(data,bit_flip_index+2);
		FLIP(data,bit_flip_index+3);
	}
	cmt = "[MUT-B-F-4]";
	if (!bit_flip_index) REPMUT(cmt);
	bit_flip_index++;

	if (bit_flip_index==(size*8)-3){
		bit_flip_index=0;
		return op+1;
	}

	if (ignore){
		ignore = 0;
		goto bit4_flip_start;
	}

	return op;
}
/*
	One byte_flip pass is run for any input and using this
	we set mut_map and find key words.
*/
size_t mut_bfi=0;
u8 byte_flip(void *data,size_t size,u8 op,size_t *start){
	static size_t byte_flip_index=0;
	u8 ignore = 0;
	u8 im_initiator = 1;

byte_flip_start:

	if (byte_flip_index > size){
		zexit("FLIP8: index out of range");
	}

	if (!im_initiator && !mut_map[byte_flip_index]){
		ignore = 1;
		*start=-1;
	}else{
		*start = byte_flip_index;

		((u8 *)data )[byte_flip_index] ^= 0xFF;
		cmt = "[MUT-B-F-8]";
		if (!byte_flip_index) REPMUT(cmt);
	}
	mut_bfi = byte_flip_index;
	byte_flip_index++;


	if (byte_flip_index==size){
		byte_flip_index=0;
		return op+1;
	}

	if (ignore){
		ignore = 0;
		goto byte_flip_start;
	}

	return op;
}

u8 byte2_flip(void *data,size_t size,u8 op,size_t *start){
	static size_t byte_flip_index=0;
	u8 ignore = 0;

byte2_flip_start:

	if (byte_flip_index > size-1){
		zexit("FLIP16: index out of range");
	}

	if (!mut_map[byte_flip_index] && !mut_map[byte_flip_index+1]){
		ignore = 1;
		*start=-1;
	}else{
		*start = byte_flip_index;

		*(u16*)&( ((u8 *)data)[byte_flip_index] ) ^= 0xFFFF;

		cmt="[MUT-B-F-16]";
		if (!byte_flip_index) REPMUT(cmt);
	}
	byte_flip_index++;

	if (byte_flip_index==size-1){
		byte_flip_index=0;
		return op+1;
	}

	if (ignore){
		ignore = 0;
		goto byte2_flip_start;
	}

	return op;
}

u8 byte4_flip(void *data,size_t size,u8 op,size_t *start){
	static size_t byte_flip_index=0;
	u8 ignore = 0;

byte4_flip_start:

	if (byte_flip_index > size-3){
		zexit("FLIP32: index out of range");
	}

	if (!mut_map[byte_flip_index] && !mut_map[byte_flip_index+1] &&
			!mut_map[byte_flip_index+2] && !mut_map[byte_flip_index+3]){
		ignore = 1;
		*start=-1;
	}else{
		*start = byte_flip_index;

		*(u32*)&( ((u8 *)data)[byte_flip_index] ) ^= 0xFFFFFFFF;

		cmt="[MUT-B-F-32]";
		if (!byte_flip_index) REPMUT(cmt);
	}
	byte_flip_index++;


	if (byte_flip_index==size-3){
		byte_flip_index=0;
		return op+1;
	}

	if (ignore){
		ignore = 0;
		goto byte4_flip_start;
	}
	return op;
}




u8 overw_8_int(void *data,size_t size,u8 op,size_t *start){
	static size_t i8_inp_index=0;
	static u8 i8_set_index = 0;
	u8 *byte;
	u8 orig_value;
	u8 ignore = 8;

overw_8_int_start:

	byte = ((u8*)data) + i8_inp_index;

	*start = i8_inp_index;

	orig_value = *byte;
	*byte = set_8_ints[i8_set_index];

	cmt = "[MUT-I-O-8]";
	if (!i8_inp_index) REPMUT(cmt);

	if (!mut_map[i8_inp_index] || bitflip_check(orig_value ^ *byte)){
		ignore = 1;
		*start=-1;
		*byte=orig_value;
	}

	i8_set_index++;

	if (i8_set_index== sizeof(set_8_ints)){
		i8_set_index = 0;
		i8_inp_index++;
	}

	if (i8_inp_index==size){
		i8_inp_index = 0;
		i8_set_index = 0;
		return op + 1;
	}

	if (ignore){
		ignore = 0;
		goto overw_8_int_start;
	}

	return op;

}

u8 overw_16_int(void *data,size_t size,u8 op,size_t *start){
	static size_t i16_inp_index=0;
	static u8 i16_set_index = 0;
	u16 *word;
	u16 orig_value;
	u8 ignore =0;

overw_16_int_start:

	word = (u16*)( ((u8*)data) + i16_inp_index );

	orig_value = *word;
	*word = set_16_ints[i16_set_index];

	*start = i16_inp_index;

	cmt = "[MUT-I-O-16]";
	if (!i16_inp_index) REPMUT(cmt);

	if ((!mut_map[i16_inp_index] && !mut_map[i16_inp_index+1]) ||
			bitflip_check(orig_value ^ *word)){
		ignore = 1;
		*start=-1;
		*word=orig_value;
	}

	i16_set_index++;

	if (i16_set_index== sizeof(set_16_ints)/2){
		i16_set_index = 0;
		i16_inp_index++;
	}

	if (i16_inp_index==size-1){
		i16_inp_index = 0;
		i16_set_index = 0;
		return op + 1;
	}

	if (ignore){
		ignore = 0;
		goto overw_16_int_start;
	}

	return op;
}

u8 overw_32_int(void *data,size_t size,u8 op,size_t *start){
	static size_t i32_inp_index=0;
	static u8 i32_set_index = 0;
	u32 *dword;
	u32 orig_value;
	u8 ignore = 0;

overw_32_int_start:

	dword = (u32*)( ((u8*)data) + i32_inp_index );

	orig_value = *dword;
	*dword = set_32_ints[i32_set_index];

	*start = i32_inp_index;

	cmt = "[MUT-I-O-32]";
	if (!i32_inp_index) REPMUT(cmt);

	if ((!mut_map[i32_inp_index] && !mut_map[i32_inp_index+1] &&
			!mut_map[i32_inp_index+2] && !mut_map[i32_inp_index+3] ) ||
			bitflip_check(orig_value ^ *dword)){
		ignore = 1;
		*start=-1;
		*dword=orig_value;
	}

	i32_set_index++;

	if (i32_set_index== sizeof(set_32_ints)/4){
		i32_set_index = 0;
		i32_inp_index++;
	}


	if (i32_inp_index==size-3){
		i32_inp_index = 0;
		i32_set_index = 0;
		return op + 1;
	}

	if (ignore){
		ignore = 0;
		goto overw_32_int_start;
	}

	return op;

}



u8 iter_intr_locs(void *data,size_t size,u8 op,size_t *start,struct inp_intr_locs *cur){
	static unsigned int intr_indx = 0;
	u8 b;

	if (intr_indx>cur->intr_locs_index){
		zexit("iter_intr_locs: i_indx out of range.");
	}

	if (!cur->intr_locs_index){
		*start=-1;
		return op+1;
	}

	if (!intr_indx){
		cmt = "[MUT-ITER-INTR-LOCS]";
		REPMUT(cmt);
	}

	*start = cur->intr_locs[intr_indx];

	b=RU8(4);
	switch(b){
		case 0:
			*(u8*)(data+cur->intr_locs[intr_indx++])=RU8(256);
			break;
		case 1:
			*(u16*)(data+cur->intr_locs[intr_indx++])=RST(0xFFFFFFFFFFFFFF);
			break;
		case 2:
			*(u32*)(data+cur->intr_locs[intr_indx++])=RST(0xFFFFFFFFFFFFFF);
			break;
		case 3:
			*(u64*)(data+cur->intr_locs[intr_indx++])=RST(0xFFFFFFFFFFFFFF);
			break;
	}

	if (intr_indx == cur->intr_locs_index ||
		cur->intr_locs[intr_indx] >= size){

		intr_indx = 0;
		return op+1;
	}

	return op;

}


u8 kw_ow_linear(void *data,size_t size,u8 op,size_t *start){
	static size_t kw_inp_index=0;
	static u8 kw_set_index = 0;
	u8 ignore = 0;

	if (!kw_index){
		*start=-1;
		return op+1;
	}

kw_ow_linear_start:

	ignore=1;

	if (keywords[kw_set_index].size + kw_inp_index -1 < size){
		if (memcmp(data+kw_inp_index,&keywords[kw_set_index].kw,keywords[kw_set_index].size)){
			if (memchr(&mut_map[kw_inp_index],1,keywords[kw_set_index].size)){
				/*
					Good. Write it.
				*/
				memcpy(data+kw_inp_index,&keywords[kw_set_index].kw,keywords[kw_set_index].size);
				ignore=0;
				*start=kw_inp_index;
			}
		}
	}


	cmt = "[MUT-KW-LINEAR]";
	if (!kw_inp_index) REPMUT(cmt);

	kw_set_index++;

	if (kw_set_index== kw_index){
		kw_set_index = 0;
		kw_inp_index++;
	}


	if (kw_inp_index==size-3){
		kw_inp_index = 0;
		kw_set_index = 0;
		return op + 1;
	}

	if (ignore){
		goto kw_ow_linear_start;
	}

	return op;
}

/* Non-iterative functions */

void mut_kw_ow(void *data,size_t size,u8 op,size_t *start,size_t *end){

	u8 kw_i;
	size_t pos;

	if (kw_index==0)
	{
		*start=-1;
		return;
	}
	cmt = "[MUT-KW-O-N]";
	REPMUT(cmt);


	kw_i = RU8(kw_index);
	pos = RST(size);

	if (keywords[kw_i].size ==0){
		zexit("mut_kw_ow: Invalid size %d %d",kw_index,kw_i);
	}
	memcpy(data + pos , (void *)keywords[kw_i].kw,keywords[kw_i].size);



	*start = pos;
	*end = pos + keywords[kw_i].size;

}

int pop=-1;

#define SIZE_LIMIT_CHECK	if (size > MAX_INPUT_SIZE )\
								zexit("mut %d, input too big, prev %d",op,pop);\
 							else if(size < MIN_INPUT_SIZE)\
								zexit("mut %d, input too small, prev %d",op,pop);\


#define INSERT_CHECK	if (size == MAX_INPUT_SIZE) {*start=-1; return;}
/*
	Insert one random keyword at a random place
	This function *increases* size
*/
void mut_kw_ins(void *data,size_t size,u8 op,size_t *start,size_t *end,size_t *new_size){
	u8 kw_i;
	size_t pos;

	SIZE_LIMIT_CHECK
	INSERT_CHECK

	if (kw_index==0)
	{
		*start=-1;
		return;
	}

	cmt = "[MUT-KW-I-N]";
	REPMUT(cmt);

	kw_i = RU8(kw_index);
	pos = RST(size);

	if (keywords[kw_i].size ==0){
		zexit("mut_kw_ins: Invalid size %d %d",kw_index,kw_i);
	}

	/*
		We use memmove which is safe for overlapping ranges
	*/
	memmove(data + pos + keywords[kw_i].size, data + pos,size-pos);
	memcpy(data + pos , (void *)keywords[kw_i].kw,keywords[kw_i].size);

	*start = pos;
	*end = pos + keywords[kw_i].size;
	*new_size = size + keywords[kw_i].size;

}

void mut_random_ow(void *data,size_t size,u8 op,size_t *start){
	long rand_i;
	size_t pos;
	int count=0;
	int tot_count=1;

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RAND-O-32]";
	REPMUT(cmt);

mut_random_ow_start:


	pos = RST(size);

	/*
		Non iterative functions don't necessarily
		work with original mutated input
		We can skip check_interesting
		of bitflip_check
	*/
	/*do{
		rand_i = (int)((rand()/(double)(((long)RAND_MAX)+1))*0xFFFFFFFF);
	}while(check_interesting(pos,rand_i));*/
	rand_i = RS64(0xFFFFFFFF);

	*(int*)(data + pos) = (int)rand_i;

	if (size>32){
		if (count++ < tot_count){
			goto mut_random_ow_start;
		}
	}
	*start = pos;
}

/*
	Insert one random integer at a random place
	This functions changes size by 4
*/
void mut_random_ins(void *data,size_t size,u8 op,size_t *start,size_t *new_size){
	long rand_i;
	size_t pos;

	SIZE_LIMIT_CHECK
	INSERT_CHECK

	cmt = "[MUT-RAND-I-32]";
	REPMUT(cmt);

	rand_i = RS64(0xFFFFFFFF);
	pos = RST(size);

	memmove(data + pos + 4 , data+pos, size-pos);
	*(int*)(data + pos) = (int)rand_i;


	*start = pos;
	*new_size=size + 4;
}

/*
	Copy a random chunk to a random location
	31 < size < 65
*/
void mut_copy_ow(void *data,size_t size,u8 op,size_t *start,size_t *end){
	size_t pos_src = RST(size-64);
	size_t pos_dst = RST(size-64);
	u8 chunk_size = 32 + RU8(33);

	if (size < 128){
		/*
			Not worth it
		*/
		*start=-1;
		return ;
	}
	cmt = "[MUT-COPY-O-N]";
	REPMUT(cmt);

	memmove(data+pos_dst,data+pos_src,chunk_size);

	*start = pos_dst;
	*end = pos_dst+chunk_size;

}

/*
	Same as above but insert
	*Increases* size
	Maximum size increase: 64

*/
void mut_copy_ins(void *data,size_t size,u8 op,size_t *start,size_t *end,size_t *new_size){
	size_t pos_src = RST(size-64);
	size_t pos_dst = RST(size-64);
	u8 chunk_size = 32 + RU8(33);
	u8 chunk[64];

	SIZE_LIMIT_CHECK
	INSERT_CHECK

	if (size < 128){
		*start=-1;
		return ;
	}

	cmt = "[MUT-COPY-I-N]";
	REPMUT(cmt);

	memcpy(chunk,data+pos_src,chunk_size);
	memmove(data+pos_dst+chunk_size,data+pos_dst,size - pos_dst);
	memcpy(data+pos_dst,chunk,chunk_size);

	*start = pos_dst;
	*end = pos_dst+chunk_size;
	*new_size= size + chunk_size;

}

void mut_shrink_size(void *data,size_t size,u8 op,size_t *start,size_t *new_size){
	size_t pos ;
	u8 chunk_size;

	SIZE_LIMIT_CHECK

	cmt = "[MUT-SHRINK-N]";
	REPMUT(cmt);

	if (size == MIN_INPUT_SIZE){
		*start=-1;
		return;
	}else if(size < 64){
		chunk_size = 1;
	}else{
		chunk_size = 16 + RU8(size/3 - 16);
	}

	pos = RST(size-(chunk_size*2));
	memmove(data+pos,data+pos+chunk_size, size - (pos+chunk_size));

	*start = pos;
	*new_size = size - chunk_size;
}


#define ADDSUB_MAX	35
#define DECREASE_PROB	if (RU8(2)){*start=-1;return;}

void mut_mix_inputs(void *data,size_t size,u8 op,size_t *start,size_t *new_size){
	int q_i;
	size_t break_pos,m_break_pos,append_size;
	FILE *mix_f;
	struct stat st;
	void *mdata;
	int c;
	u8 *p;

	SIZE_LIMIT_CHECK
	DECREASE_PROB


	cmt = "[MUT-MIX-N]";
	REPMUT(cmt);
	if (queue_ind==1){
		/*
			This input is the only
			input in the queue. (q_i=zero)
		*/
		*start = -1;
		return;
	}

mut_mix_inputs_start:

	q_i = RS32(queue_ind);

	if (q_i == queue_use_ind){
		goto mut_mix_inputs_start;
	}

	if (lstat(input_queue[q_i].i_path,&st)==-1){
		zexit("mix_inputs: stat: %s | %d %d %d",strerror(errno),q_i,queue_ind,queue_use_ind);
	}

choose_offsets:
	break_pos = RST(size);
	m_break_pos = RST(st.st_size);

	if (break_pos + (st.st_size - m_break_pos) < MIN_INPUT_SIZE){
		goto choose_offsets;
	}

	mix_f = fopen(input_queue[q_i].i_path,"r");
	if (!mix_f){
		zexit("mix_inputs: fopen()");
	}



	if (fseek(mix_f,m_break_pos,SEEK_SET)==-1){
		zexit("mix_inputs: fseek");
	}

	mdata = mmap(0,(st.st_size - m_break_pos), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);
	if (mdata==MAP_FAILED){
		zexit("mix_inputs: madata");
	}

	p = mdata;
	while((c=fgetc(mix_f)) != -1){
		*p++ = c;
	}
	fclose(mix_f);

	/*
		Careful about size here
		Don't overflow data in local memory
	*/

	append_size = (st.st_size - m_break_pos)   ;
	append_size = append_size + break_pos <= MAX_INPUT_SIZE ? append_size :
															MAX_INPUT_SIZE - break_pos;


	memcpy(data+break_pos,mdata,append_size);

	*new_size = break_pos + (st.st_size - m_break_pos);

	if (munmap(mdata,st.st_size - m_break_pos)){
		zexit("mix_inputs: munmap()");
	}

	*start=break_pos;
}


void mut_rand_flip(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size<<3);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RAND-FLIP-1]";
	REPMUT(cmt);

	FLIP(data,pos);

	*start = pos >> 3;

}

#define SW16(x) ({\
					u16 d16 = (u16)x;\
					(u16)((d16<<8)|(d16>>8));\
				})

#define SW32(x) ({\
					u32 d32 = x;\
					(u32)((d32<<24)|(d32>>24)|\
						((0x00FF0000 & d32)>>8)|\
						((0x0000FF00 & d32)<<8));\
				})

void mut_over_rand_8_int(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-OVER-RAND-8-INT]";
	REPMUT(cmt);
	*(u8*)(data + pos) = set_8_ints[RU8(sizeof(set_8_ints))];

	*start = pos;
}

void mut_over_rand_16_int(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size-1);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-OVER-RAND-16-INT]";
	REPMUT(cmt);

	*(u16*)(data + pos) = RU8(2) ? set_16_ints[RU8(sizeof(set_16_ints))]:
								SW16(set_16_ints[RU8(sizeof(set_16_ints))]);

	*start = pos;

}

void mut_over_rand_32_int(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size-3);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-OVER-RAND-32-INT]";
	REPMUT(cmt);

	*(u32*)(data + pos) = RU8(2) ? set_32_ints[RU8(sizeof(set_32_ints))]:
								SW32(set_32_ints[RU8(sizeof(set_32_ints))]);
	*start = pos;
}

void mut_rand_8_add_sub(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RAND-8-ADSB]";
	REPMUT(cmt);

	if (RU8(2)){
		*(u8*)(data + pos) += RU8(ADDSUB_MAX);
	}else{
		*(u8*)(data + pos) -= RU8(ADDSUB_MAX);
	}

	*start = pos;
}

void mut_rand_16_add_sub(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size-1);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RAND-16-ADSB]";
	REPMUT(cmt);

	if (RU8(2)){
		*(u16*)(data + pos) += 1+RU8(ADDSUB_MAX);
	}else{
		*(u16*)(data + pos) -= 1+RU8(ADDSUB_MAX);
	}

	*start = pos;
}

void mut_rand_32_add_sub(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size-3);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RAND-32-ADSB]";
	REPMUT(cmt);

	if (RU8(2)){
		*(u32*)(data + pos) += 1+RU8(ADDSUB_MAX);
	}else{
		*(u32*)(data + pos) -= 1+RU8(ADDSUB_MAX);
	}

	*start = pos;
}

void mut_rand_8_byte(void *data,size_t size,u8 op,size_t *start){
	size_t pos= RST(size);

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RAND-8-BYTE]";
	REPMUT(cmt);

	*(u8*)(data + pos)=RU8(256);

	*start = pos;
}


void mut_insert_const(void *data,size_t size,u8 op,size_t *start,size_t *end,size_t *new_size){
	size_t pos= RST(size);
	size_t len = 4 + RST((size/3));
	u8 val;

	SIZE_LIMIT_CHECK
	INSERT_CHECK
	DECREASE_PROB

	cmt = "[MUT-INSERT-CONST]";
	REPMUT(cmt);

	if (len + size > MAX_INPUT_SIZE){
		*start = -1;
		return;
	}

	val = RU8(2) ? RU8(256) : *(u8 *)(data + pos);
	memmove(data + pos + len,data+pos,size-pos);
	memset(data+pos,val,len);

	*new_size = size + len;

	*start = pos;
	*end=*start+len;
}


void mut_ow_const(void *data,size_t size,u8 op,size_t *start){
	size_t len = 4 + RST((size/3)-4);
	size_t pos = RST(size-len+1);
	u8 val;

	SIZE_LIMIT_CHECK

	cmt = "[MUT-OW-CONST]";
	REPMUT(cmt);

	val = RU8(2) ? RU8(256) : *(u8 *)(data + pos);

	memset(data+pos,val,len);

	*start = pos;
}

void mut_sw_bytes(void *data,size_t size,u8 op,size_t *start){
	size_t pos1=RST(size);
	size_t pos2;
	u8 t;

	SIZE_LIMIT_CHECK

	cmt = "[MUT-SW-BYTES]";
	REPMUT(cmt);

	do{
		pos2=RST(size);
		if (pos2 != pos1 )
			break;
	}while(1);

	/*
		We may have a data buffer whose all/most
		bytes are all equal. We don't want to waste
		a lot of time here.
	*/
	if (*(u8*)(data + pos1)==*(u8*)(data + pos2))
	{
		*start = -1;
		return;
	}

	t=*(u8*)(data + pos1);
	*(u8*)(data + pos1)=*(u8*)(data + pos2);
	*(u8*)(data + pos2)=t;

	*start = pos1;

}


void mut_ow_rand_chunk(void *data,size_t size,u8 op,size_t *start){
	size_t pos = RST(size-size/4);
	u8 *chunk=malloc(size/4);
	size_t i;

	SIZE_LIMIT_CHECK

	cmt = "[MUT-RND-CHUNK]";
	REPMUT(cmt);

	for (i=0;i<size/4;i++){
		chunk[i] = RU8(256);
	}

	memcpy(data+pos,chunk,size/4);

	*start=pos;

	free(chunk);
}


void mut_scatter_rand(void *data,size_t size,u8 op,size_t *start){
	size_t pos;
	size_t i;

	SIZE_LIMIT_CHECK

	cmt = "[MUT-SCATTER-RND]";
	REPMUT(cmt);

	for (i=0;i<size/4;i++){
		pos = RST(size);
		*(u8*)(data+pos) = RU8(256);
	}

	*start = 0;

}


void mut_intr_locs(void *data,size_t size,u8 op,size_t *start,struct inp_intr_locs *cur){
	size_t pos;
	int i,si,i_indx = cur->intr_locs_index;
	u8 b;

	if (i_indx>MAX_INTR_LOCS || i_indx<0){
		zexit("mut_intr_locs: i_indx out of range.");
	}

	if (!i_indx){
		*start=-1;
		return;
	}



	cmt = "[MUT-INTR-LOCS]";
	REPMUT(cmt);

	/*
		Since intr_locs is inherited
		we should check not to go beyond
		the size of this input
	*/
	for (i=0;i<i_indx;i++){
		if (cur->intr_locs[i] >= size){
			i_indx = i;
			break;
		}
	}

	/*
		Set to random value for log(i_indx) times
	*/
	si = i_indx;
	do{
		pos = cur->intr_locs[RST(i_indx)];
		b=RU8(4);
		switch(b){
			case 0:
				*(u8*)(data+pos)=RU8(256);
				break;
			case 1:
				*(u16*)(data+pos)=RST(0xFFFFFFFFFFFFFF);
				break;
			case 2:
				*(u32*)(data+pos)=RST(0xFFFFFFFFFFFFFF);
				break;
			case 3:
				*(u64*)(data+pos)=RST(0xFFFFFFFFFFFFFF);
				break;
		}
		si/=2;
	}while(si);

	*start = pos;

}

void print_dict_kws(){
	int i;
	for (i=0;i<dict_kw_count;i++){
		char tmp[100];
		strcpy(tmp,dict_kws[i]);
		printf("%d '%s'\n",i,tmp);
	}

}

void mut_dict_kw_ow(void *data,size_t size,u8 op,size_t *start,size_t *end){

	int kw_i;
	size_t pos;
	char keyword[DICT_MAX_KW_SIZE+1];
	int kwlen;

	if (!dict_file){
		zexit("Requested dictionary operation while no dictionary has been given. (OW)");
	}

	cmt = "[MUT-DICT-KW-O]";
	REPMUT(cmt);


	kw_i = RS32(dict_kw_count);
	strcpy(keyword,dict_kws[kw_i]);
	kwlen = strlen(dict_kws[kw_i]);

	if (kwlen==0){
		zexit("Invalid kw len");
	}

	pos = RST(size);

	memcpy(data + pos , (void *)keyword,kwlen);



	*start = pos;
	*end = pos + kwlen;

}


void mut_dict_kw_ins(void *data,size_t size,u8 op,size_t *start,size_t *end,size_t *new_size){
	int kw_i;
	size_t pos;
	char keyword[DICT_MAX_KW_SIZE+1];
	int kwlen;

	SIZE_LIMIT_CHECK
	INSERT_CHECK

	if (!dict_file){
		zexit("Requested dictionary operation while no dictionary has been given. (INS)");
	}

	cmt = "[MUT-DICT-KW-I]";
	REPMUT(cmt);

	kw_i = RS32(dict_kw_count);
	strcpy(keyword,dict_kws[kw_i]);
	kwlen = strlen(dict_kws[kw_i]);

	pos = RST(size);

	memmove(data + pos + kwlen, data + pos,size-pos);

	memcpy(data + pos , (void *)keyword,kwlen);

	*start = pos;
	*end = pos + kwlen;
	*new_size = size + kwlen;

}

/*********** End mutation functions ************/

void write_g_input(u8 *data,size_t size){

	if (file_feed){
		FILE *out_f;
		size_t n;

		out_f = fopen(feed_file_path,"w");
		if (!out_f){
			zexit("open() : generated input");
		}
		if ((n=fwrite(data,1,size,out_f)) <size){
			zexit("write() : generated input");
		}
		fclose(out_f);
	}else{
		u8 *p=data;
		u8 *end=data+size;
		size_t chk_sz=0;

		lseek(feed_fd,0,SEEK_SET);

		while(p<end){
			if (end-p > 2048){
				chk_sz=2048;
			}else{
				chk_sz=end-p;
			}

			if (write(feed_fd,p,chk_sz)!=chk_sz){
				zexit("write");
			}

			p+=chk_sz;
		}

		if (ftruncate(feed_fd,size))
			zexit("can't truncate current input");

		lseek(feed_fd,0,SEEK_SET);

	}

}

int feed_net(void *data,long size){
	long n;
	char buf[1<<16];
	int ret=-1;
	u8 soft_crash = 0;


	reset_structures();


	/*
		send data and wait for TCP response
	*/
	if (save_net){
		save_netdata(data,size,NET_FILE);
	}
	n=send(net_sock,data,size,0);

	if (n<size){
		zexit("send failed ");
		goto check_failure;
	}
	/*
		We expect the target to respond
		immediately
	*/
	buf[0]=0;
	n=recv(net_sock,buf,(1<<16),0);
	if (n<=0){

		if (errno==ERR_TMOUT){
			soft_crash=1;
		}else{
			/*
				recv failed for a reason other than timeout
			*/
		}
		goto check_failure;
	}

	if (!reconnect()){
		soft_crash=1;
		goto check_failure;
	}

	return TRG_NET_MODE;

check_failure:
	/*
		kill target if it's still running
		poll fork server and see what happened
		The exit status must be either crash or
		kill signal in this situation
	*/


	ret = do_term_check();
	if (ret == TRG_EX_TMOUT || ret == TRG_EX_NORMAL){
		if (soft_crash){
			return TRG_SOFT_CRASH;
		}
	}
	return ret;

}



int feed_ex_target(void *data,u64 size){
	int result;

	total_exec++;

	if (net_mode && target_id){
		result = feed_net(data,size);

		return result;
	}else{
		if (net_mode){
			if (save_net){
				save_net_i = 0;
			}

			execute(0);
			return feed_net(data,size);
		}else{
			write_g_input(data,size);
			return execute(0);
		}
	}

}
void save_rep(u8 soft_crash,u8 * data,size_t size){
	FILE *crash_input;
	char filename[1064];
	size_t n;
	u32 i_hash;
	int i;

	i_hash = do_hash();


	for (i=0;i<crash_sums_index;i++){
		if (crash_sums[i] == i_hash)
			return; //we've already seen it
	}
	crash_sums[crash_sums_index++] = i_hash;

	if (crash_sums_index == CRASH_MAX) //Unlikely
		crash_sums_index=0;

	if (soft_crash){
		sprintf(filename,"%s/crashes/crash%d_SOFT_",output_dir,crash_rep++);
		unique_soft_crashes++;
	}
	else{
		sprintf(filename,"%s/crashes/crash%d_%s_M%d",output_dir,crash_rep++,
							get_sig_name(last_crash_sig),last_crash_mut);
		unique_crashes++;
	}
	crash_input=fopen(filename,"w");
	if (!crash_input){
		zexit("save_rep: open failed");
	}
	if ((n=fwrite(data,size,1,crash_input))<1){
		zexit("save_rep: write failed");
	}
	fclose(crash_input);

	if (soft_crash){
		//zrep("Potential DOS [input saved]");
	}
	output_count++;

}
void live_rep(){
	FILE *frep=fopen(LIVE_REP_FILE,"r+");
	char line[1024];
	int i=0;


	if (!frep){
		zexit("open failed: live report file");
	}
	/*

		line1: start time
		line2: target name
		line3: total blocks
		line4: indp blocks
		line5: nested blocks

		rest is dynamic data that we should update

		Report:
			total coverage (number of blocks hit so far)
			total target hits
			number of independent blocks covered
			number of nested blocks	covered

	*/
	if (fseek(frep,0,SEEK_SET)==-1){
		zexit("fseek(): live report");
	}

	line[0]=0;
	for (i=0;i<5;i++){
		if (!fgets(line,1024,frep)){
			zexit("fgets(): live report file: %s",strerror(errno));
		}
	}

	if ((fprintf(frep,"%lu\n%lu\n%lu\n%lu\n%lu\n",total_covered
							,total_target_hits
							,indp_counter
							,nested_counter
							,last_trace_nodes))
		<0)
		zexit("write(): live report");

	fclose(frep);


}
void save_mutated_input(u8 *data,size_t size){
	FILE *mut_input;
	char filename[1064];
	size_t n;

	sprintf(filename,"%s/saved_input%d",input_dir,mut_input_saved++);
	mut_input=fopen(filename,"w");
	if (!mut_input){
		zexit("save_rep: open failed");
	}
	if ((n=fwrite(data,size,1,mut_input))<1){
		zexit("save_rep: write failed");
	}
	fclose(mut_input);

}

void add_stat_entry(){
	FILE *f;
	time_t cur_time;

	time(&cur_time);
	cur_time-=start_time;

	f=fopen(STAT_ENTRIES_FILE,"a");
	if (!f){
		zexit("add_stat_entrey: fopen");
	}
	fprintf(f,"<%s> %lu:%lu:%lu\n",cmt,total_covered,total_exec,cur_time);
	fclose(f);
}

void balance_lps(int first_ind){
	int last=queue_ind-1,mid;
	int i;
#define SW_PROB	(!RU32(20))  //5%

	if (last < first_ind){
		/*
			Cycled queue
			Very unlikey to happen when this
			function is called.
		*/
		last = INPUT_MAX-1;
	}

	mid = ((last-first_ind)+1)/2;

	for (i=first_ind;i<mid;i++){
		if (SW_PROB){
			int swi;
			struct input_val tmp;
			/*
				Switch this with a random lp
				in the second half
			*/
			swi = mid + RU32(last-mid) +1;

			if (swi >= INPUT_MAX){
				/*
					Diffinetly impossible but just in case
					if I made a mistake in above lines.
				*/
				zexit("Unexpected index to switch lp.");
			}
			if (input_queue[i].prio>0 || input_queue[swi].prio>0){
				//print_queue();
				zexit("Non lp input in lp balance %d %d %d %d",i,swi,queue_use_ind,queue_ind);
			}
			tmp = input_queue[i];
			input_queue[i]=input_queue[swi];
			input_queue[swi] = tmp;

		}
	}

}
u8 kw_is_new(u8 *data,size_t len){
	int i;

	if (len==4){
		for (i=0;i<sizeof(set_32_ints)/4;i++){
			if ((*(u32*)data) == set_32_ints[i])
				return 0;

		}
	}
	for (i=0;i<kw_index;i++){
		if (!memcmp(data,&keywords[i].kw,len))
			return 0;

	}
	return 1;
}
void zharf_generate(){
	void *saved_input;
	void *mutated_input;
	u8 *p;
	struct stat st;
	u64 alloc_size;
	size_t actual_size;
	size_t mutated_size;
	FILE *f_in;
	FILE *f_out;
	char f_o_path[1064];
	int c;
	u8 mut_op=0,mut_op_used;
	u8 mutation_finished = 0;
	int t_exit_stat;
	u8 should_store = 0;
	size_t m_start,m_end;
	u64 last_kw_pos = 0;
	u8 must_refresh_input = 0;
	u64 ni_counter = 0;
	u64 ni_total_tries=0;
	int ni_burst_counter=0;
#define BURST_P_MIN	1
	int ni_mut_burst=BURST_P_MIN;
	u64 ni_exec_total=0;
	u8 it_end=10;
	u8 ni_start=15;
	u8 ni_functions_count = 22 + (dict_file?2:0);
	//u64 total_covered_sav;

	struct inp_intr_locs *cur_intr_locs;

	u8 tm_perfcheck=0,tm_perfcheck_prev;
	u8 candidate_useful;
	int set_check_burst=0;
	int unset_check_burst=0;
	int init_check_burst=0;
#define INIT_CH_BURST	32
#define SET_CH_BURST	20
#define UNSET_CH_BURST	5



#define NI_MAX_ROUNDS_INIT	(1<<(19 + BURST_P_MIN))
#define NI_MAX_ROUNDS_MUT	(1<<(16 + BURST_P_MIN))

#define NI_REF_PROB_WEIGTH	0.5

#define NI_MAX_ROUNDS	((input_queue[queue_use_ind].initial) ? NI_MAX_ROUNDS_INIT : NI_MAX_ROUNDS_MUT)



	//int max_depth_sav;

	/*
		Load the whole input in memory
		change as needed
		write changed input in current_input
		execute()

	*/


	if (lstat(input_queue[queue_use_ind].i_path,&st)==-1){
		zexit("generator: stat");
	}

	actual_size = st.st_size;

	if (actual_size > MAX_INPUT_SIZE || actual_size < MIN_INPUT_SIZE){
		zexit("Input %s: Invalid size",input_queue[queue_use_ind].i_path);
	}
	/*
		Allocate at most 2KB more than
		the actual size for the synthesized input
	*/
	alloc_size = MAX_INPUT_SIZE*2;//((actual_size/1024)+2)*1024;// == actual_size ? actual_size : ((actual_size/1024)+1)*1024 ;
	saved_input = mmap(0,alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);
	mutated_input = mmap(0,alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);

	if (saved_input==MAP_FAILED || mutated_input==MAP_FAILED){
		zexit("generator failed due to memory inaccessiblity");
	}
	f_in = fopen(input_queue[queue_use_ind].i_path,"r");
	if (!f_in){
		zexit("generator: open failed");
	}
	p = saved_input;
	while((c=fgetc(f_in)) != -1){
		*p++ = c;
	}
	fclose(f_in);

	/*********** Variable initializations of the input here ***************/

	/*
		For lpq_balance==1:
		If this is the first lp input to use,
		perform a one time lp balane.
	*/
	if (pm_mode!=2){ //in TNS mode, there's not a sorted queue
		if (lpq_balance==1 && !visited_lp && input_queue[queue_use_ind].prio==0){
			balance_lps(queue_use_ind);
			visited_lp=1;
		}
	}
	if (input_queue[queue_use_ind].initial && !input_queue[queue_use_ind].passed){
		/*
			crete a new interesting locs map
			that will be inherited by the inputs
			createed from this input
		*/
		cur_intr_locs = malloc(sizeof(struct inp_intr_locs));
		if (!cur_intr_locs){
			zexit("cur_intr_locs, malloc");
		}
		cur_intr_locs->intr_locs_index = 0;
		input_queue[queue_use_ind].i_intr_locs = cur_intr_locs;
	}else{
		cur_intr_locs = input_queue[queue_use_ind].i_intr_locs;
		if (cur_intr_locs==0){
			zexit("cur_intr_locs is NULL");
		}
		if (cur_intr_locs->intr_locs_index == 0){
			zwarn("Input with empty INTR set (target with static behavior?)");
		}
	}


	memset(mut_map,0,MAX_INPUT_SIZE);
	mut_map[0]=1;

	need_csum = 1;

	/*
		Update keywords for the input
	*/
	kw_index=0;

	/*
		Set dynamic performance check when
		the requested performance check is 1.
		This is only in effect for lp inputs.
	*/
	if (perf_check_req ==1){
		if (input_queue[queue_use_ind].prio>0){
			perf_check = 1;
		}else {
			if (RU8(4)){//75%
				perf_check = 2; //speed up low prio processing for this input
			}else{
				perf_check = 1; //revert back to 1 if it's 2 from previous round
			}
		}
	}


	/**********************************************************************/

u64 tcount=0;

	while(!mutation_finished){
		struct input_val new_input;

		if (ni_counter){
			/*
				ni_counter == 1 ends this
			*/
			ni_total_tries++;
			if (m_start!=-1) ni_counter--;
			if (ni_total_tries > 2*NI_MAX_ROUNDS){
				mut_op = 255;
				zwarn("Input stayed for too many tries in NI stage");
			}else{
				if (ni_counter==0){
					mut_op = 255;
				}else{
					mut_op = ni_start + RU8(ni_functions_count);
					if (!dict_file && mut_op>36)
						zexit("Invalid mut for non-dict mode.");

				}
			}
		}


		if (mut_op < ni_start || must_refresh_input){
			memcpy(mutated_input,saved_input,actual_size);
			mutated_size = actual_size;
			must_refresh_input = 0;
		}

		/* ALL loop initializations here */

		m_start = (size_t)-1; //~0UL
		m_end =(size_t)-1;
		has_corrupted_shm = 0;
		//max_depth_sav = max_depth;
		//total_covered_sav = total_covered;
		candidate_useful = 0;
		tm_perfcheck_prev = tm_perfcheck;

		/********************************/

/*
	Change muts that don't seem to be useful for strcutured
	inputs to dict mut
*/
#define CHECK_FOR_STRUCTURED() if (dict_file){\
									if (RU8(2))\
										mut_dict_kw_ow(mutated_input,mutated_size,mut_op,&m_start,&m_end);\
									else\
										mut_dict_kw_ins(mutated_input,mutated_size,mut_op,&m_start,&m_end,&mutated_size);}

		mut_op_used = mut_op;
		switch (mut_op){
			case 0:
				mut_op=byte_flip(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+1;

				break;
			case 1:
				/*
					hash operation is very expensive even with
					simple hash algorithms. Limit its use to
					only bit_flip()
				*/
				need_csum=0;

				if (perf_check==2){
					active_timeout = active_timeout_sav;
					tm_perfcheck = 0;
				}

				if (input_queue[queue_use_ind].prio == 0){
					/*
						Dismiss the rest of flip functions.
					*/
					mut_op = 6;
					continue;
				}else if(input_queue[queue_use_ind].passed){
					/*
						We are traversing the queue from beginning
						Skip all next iterative functions.
					*/
					ni_counter = NI_MAX_ROUNDS;
					continue;
				}


				mut_op=bit_flip(mutated_input,actual_size,mut_op,&m_start);

				/*
					only one byte changes
				*/
				m_end=m_start+1;

				break;
			case 2:
				mut_op=bit4_flip(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 3:
				mut_op=bit2_flip(mutated_input,actual_size,mut_op,&m_start);

				m_end=m_start+1;
				break;
			case 4:
				mut_op=byte2_flip(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+2;
				break;
			case 5:
				mut_op=byte4_flip(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+4;
				break;

			case 6:
				mut_op=overw_8_int(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 7:
				mut_op=overw_16_int(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+2;
				break;
			case 8:
				mut_op=overw_32_int(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+4;
				if (mut_op==9){
					/*
						If too few interesting locs, inherit it.
					*/
					if (cur_intr_locs->intr_locs_index < MIN_INTR_LOC_COUNT && queue_use_ind > 0
						&& input_queue[queue_use_ind].initial &&
						input_queue[0].i_intr_locs->intr_locs_index > cur_intr_locs->intr_locs_index){
						/*
							Use the first input intr_locs
						*/
						memcpy(cur_intr_locs,input_queue[0].i_intr_locs,sizeof(struct inp_intr_locs));
					}
				}
				break;
			case 9:
				mut_op=iter_intr_locs(mutated_input,actual_size,mut_op,&m_start,cur_intr_locs);
				m_end=m_start+1;

				break;
			case 10:
				mut_op=kw_ow_linear(mutated_input,actual_size,mut_op,&m_start);
				m_end=m_start+1;
				if (mut_op == it_end+1){ /* Prepare for non iterative mutators */
					ni_counter = NI_MAX_ROUNDS;
				}
				break;

			/*
				Non iterative start
				Mutated size is used instead of actual size
				since the input is now dynamic
			*/
			case 15:
				mut_kw_ow(mutated_input,mutated_size,mut_op,&m_start,&m_end);
				break;
			case 16:
				mut_kw_ins(mutated_input,mutated_size,mut_op,&m_start,&m_end,&mutated_size);
				break;
			case 17:
				//CHECK_FOR_STRUCTURED();

				mut_random_ow(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+4;
				break;
			case 18:
				//CHECK_FOR_STRUCTURED();

				mut_random_ins(mutated_input,mutated_size,mut_op,&m_start,&mutated_size);
				m_end=m_start+4;
				break;
			case 19:
				mut_copy_ow(mutated_input,mutated_size,mut_op,&m_start,&m_end);
				break;
			case 20:
				mut_copy_ins(mutated_input,mutated_size,mut_op,&m_start,&m_end,&mutated_size);
				break;
			case 21:
				mut_shrink_size(mutated_input,mutated_size,mut_op,&m_start,&mutated_size);
				m_end=m_start+1;
				break;
			case 22:
				mut_sw_bytes(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;

			case 23:
				mut_rand_flip(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 24:
				mut_over_rand_8_int(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 25:
				mut_over_rand_16_int(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+2;
				break;
			case 26:
				mut_over_rand_32_int(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+3;
				break;
			case 27:
				mut_rand_8_add_sub(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 28:
				mut_rand_16_add_sub(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+2;
				break;
			case 29:
				mut_rand_32_add_sub(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+3;
				break;
			case 30:
				mut_rand_8_byte(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 31:

				CHECK_FOR_STRUCTURED();

				mut_insert_const(mutated_input,mutated_size,mut_op,&m_start,&m_end,&mutated_size);

				break;
			case 32:
				CHECK_FOR_STRUCTURED();

				mut_ow_const(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 33:
				mut_mix_inputs(mutated_input,mutated_size,mut_op,&m_start,&mutated_size);
				/*
					This check shouldn't be necessary
					I haven't done it for flip functions
					but just to play the role of a reminder
					that m_end might incorrectly be set to 0
					if not checked
				*/
				if (m_start!=-1){
					m_end=m_start+1;
				}
				break;
			case 34:
				CHECK_FOR_STRUCTURED();

				mut_ow_rand_chunk(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 35:

				mut_scatter_rand(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;

				break;
			case 36:

				mut_intr_locs(mutated_input,mutated_size,mut_op,&m_start,cur_intr_locs);

				m_end=m_start+1;
				break;

			/*
				Dictionary muts
				These must be the last two muts
			*/
			case 37:
				mut_dict_kw_ow(mutated_input,mutated_size,mut_op,&m_start,&m_end);

				break;
			case 38:
				mut_dict_kw_ins(mutated_input,mutated_size,mut_op,&m_start,&m_end,&mutated_size);
				break;
			default: //255
				mutation_finished =1 ;

				break;

		}

#ifdef _DEBUG
process_exec:
#endif
		pop=mut_op;
		if (mutation_finished){
			break;
		}



		if (m_start == -1){
			/*
				Ignore this mut result.
				Either the called mut function didn't accept
				the input or it's not useful for exec.
			*/
			if (mut_op>=ni_start){
				tcount++;
				if (tcount>10){
					zwarn("Detected poor NI response from target");
				}
			}
			continue;
		}
		tcount=0;
		/*************************************************************************************
			Fix potential problems in the generated inputs
			Do input-based tasks in general
		*/
		/*
			Check and trim generated input if it's
			bigger than allowed. This may happen after
			insertion functions.
			What's important is that we don't save
			anything beyond the size limit as violating
			this will break fuzzing logic regarding mut_map
		*/
		if (mutated_size > MAX_INPUT_SIZE){
			mutated_size = MAX_INPUT_SIZE;
		}

		/*
			mut functions are supposed not to return anything
			smaller tha minimum bound.
		*/
		if (mutated_size < MIN_INPUT_SIZE){
			zexit("Current mut: %d - Detected too small input: %d",mut_op,mutated_size);
		}
		/*
			Since the save_debug info will only be called while this
			funtion's stack frame is still alive we can have debug_data
			safely point to data

		*/
		debug_data=(u8*)mutated_input;
		debug_data_size=mutated_size;



		/******************************************************************************/


		if (mut_op >= ni_start){
			ni_burst_counter++;

			if (ni_counter==1 || ni_burst_counter == ni_mut_burst){
				ni_burst_counter = 0;
				must_refresh_input = 1;
				ni_mut_burst = 1 << (BURST_P_MIN + RU8(7));
				ni_exec_total++;
			}else{
				/*
					Nope, carry on mutating
				*/
				continue;
			}

		}

#ifdef RECORD_FEEDS
		if (net_mode){
			record(mutated_input,mutated_size);
		}
#endif

		t_exit_stat=feed_ex_target(mutated_input,mutated_size);

		if (net_mode && !shared_trace_tree->root){
			/*
				We don't consider this a memory fault
				This is a strong sign that target has already died
				and packets are received by another instance
				of the target not run by zharf

				What happens in this scenario is that target
				is executed by zharf but dies soon because
				for example the src port is in use. However
				since the port is open in another instance
				outside the context of fuzzer, packets are
				delivered correctly to that instance instead
				of our executed instance. In this case fuzzer
				thinks target is still alive.
			*/
			zwarn("Detected potential pre-mature death in target.");

		}
		debug_exit_code = t_exit_stat;


		/*
			Any access to shared memory for
			multithread programs in network mode
			must be locked since the program is alive
		*/

		ACQUIRE_LOCK_CONDITIONED
		eval_tree(&new_input);

		c=coverage_changes();
		RELEASE_LOCK


		if (c>0){
			int add_indx=-1;

			sprintf(f_o_path,"%s/q/g_input_%d",output_dir,save_i_count);

			/*
				Consider adding to queue
			*/
			strcpy(new_input.i_path,f_o_path);
			new_input.prio= (c==2?0:1);
			new_input.passed = 0;
			new_input.leaves = 0;
			new_input.fixed_loc = 0;
			new_input.marked=marked_tree;
			new_input.i_intr_locs = cur_intr_locs;
			if (queue_add_traced(&new_input,&add_indx)){
				f_out = fopen(f_o_path,"w");
				if (!f_out){
					zexit("generator: out_open");
				}
				fwrite(mutated_input,mutated_size,1,f_out);
				fclose(f_out);

				if ((add_indx < queue_use_ind && queue_hit_sl==0) ||
					add_indx < 0 ||
					add_indx > INPUT_MAX){

					zexit("Queue violation: Input %s, QI %d, QA %d, prio %d",
					f_o_path,queue_use_ind,add_indx,new_input.prio);
				}


				save_i_count++;
				candidate_useful=1;

			}

		}else if(c==-1){
			/*
				Map is corrupted
				One important reason can be timeout
				when the target is terminated while
				libzh is running
				This can or cannot be an intersting
				case.
				We'd better disregard it as a regular timeout
				like when target is waiting for user input
				But if it's not timeout then it can be dereferencing
				a wrong pointer in the target itself which has
				ended up in the shared memory.
				So it's possible that it's an interesting case.
			*/

			has_corrupted_shm = 1;
		}else{
			//pass
		}

		if (use_term_gui && brefr_freq_counter++ == brefr_freq){
			refresh_board(mutated_input,mutated_size,m_start,m_end);
			/*
				brefr_freq is dynamic and changes afte calling
				refresh_board()
			*/
			brefr_freq_counter=0;
		}

		/*
			We build the mutation map here and
			only for byte_flip. Along with mut_map
			keywords are also identified.
		*/
		if (mut_op == 0){
			if (m_start >= MAX_INPUT_SIZE){
				zexit("There's an invalid input in the queue.");
			}


			if (current_csum != last_csum){
				mut_map[m_start] = 1;
				last_csum = current_csum;
				/*
					Check if we have any free slot in keywords
				*/
				if (kw_index < MAX_KEYWORDS ){
					u64 kw_len = m_start - last_kw_pos;

					if (kw_len >2 && kw_len<= MAX_KW_SIZE){
						if ( kw_is_new(mutated_input+last_kw_pos,kw_len)){
							memcpy(&keywords[kw_index].kw,mutated_input+last_kw_pos,kw_len) ;
							keywords[kw_index].size = (u8)kw_len;
							last_kw_pos = m_start;

							kw_index++;
						}
					}
				}
			}else{
				/*
					else corresponding element remains zero
					dismiss this byte
				*/
				//if (!mut_map[m_start])printf("Skip %lu\n",m_start);
			}




			/*
				We  check performance here
				Last kw pos has already been saved
				We may zero current mut_map element
				We may reduce timeout
			*/
			if (input_queue[queue_use_ind].initial){
				/*
					It's worth to spend a little more time
					on the initial inputs.
					Dismiss performance check.
				*/

			}
			else if (!perf_check){
				/*
					Perfomance check is disabled
					per user request.
				*/

			}else if(perf_check == 1){
				/*
					Build map based on candidate_useful
					Don't change timeout.
					For low priority inputs, next iterative functions
					will be ignored regardless.
				*/
				mut_map[m_start]= candidate_useful;

			}else if(perf_check == 2){
				/*
					Build based on candidate_useful
					and adjust timeout
				*/
				mut_map[m_start]= candidate_useful;
				if (!candidate_useful){
					if (init_check_burst < INIT_CH_BURST){
						init_check_burst++;
					}else{
						if (set_check_burst== SET_CH_BURST){
							if (unset_check_burst == UNSET_CH_BURST){
								set_check_burst = 0;
								unset_check_burst = 0;
								active_timeout = MIN_TIMEOUT_VAL;
								tm_perfcheck=1;
							}else{
								active_timeout = active_timeout_sav;
								tm_perfcheck=0;
								unset_check_burst++;
							}
						}else{
							active_timeout = MIN_TIMEOUT_VAL;
							tm_perfcheck=1;
							set_check_burst++;

						}
					}
					mut_map[m_start]=0;
				}else{
					active_timeout = active_timeout_sav;
					set_check_burst = 0;
					unset_check_burst = 0;
					if (init_check_burst < INIT_CH_BURST){
						init_check_burst = 0;
					}
				}
			}else{
				zexit("Invalid perf_check mode");
			}

		}



		if(mut_op < it_end){
			/*
				Iterative functions can help us
				find interesting locations accurately
				iter_intr_locs is not used for this.
			*/
			if (input_queue[queue_use_ind].initial && cur_intr_locs->intr_locs_index < MAX_INTR_LOCS
				&& candidate_useful){
				int i;

				for (i=0;i<cur_intr_locs->intr_locs_index;i++){
					if (cur_intr_locs->intr_locs[i]==m_start){
						i=-1;
						break;
					}
				}
				if (i!=-1)
					cur_intr_locs->intr_locs[cur_intr_locs->intr_locs_index++] = m_start;

			}

		}


		if (t_exit_stat==-1){
			zexit("Unexpected state (%d) in target execution. (generator)",t_exit_stat);
		}
#define CHECK_ABNORMAL_MEMFAULT if (has_corrupted_shm){\
									save_rep(1,(u8*)mutated_input,mutated_size);\
									zwarn("Detected possible memory fault. Input saved.");\
								}\

		if (target_id && t_exit_stat == TRG_NET_MODE){
			/*
					only happens in network mode
					target is alive and has responded to
					our input.
			*/
			CHECK_ABNORMAL_MEMFAULT
		}else{
			if (t_exit_stat == TRG_EX_NORMAL){
				CHECK_ABNORMAL_MEMFAULT
			}else if (t_exit_stat == TRG_SOFT_CRASH ){
				if (save_soft_crash){
					soft_crashes++;
					save_rep(1,(u8*)mutated_input,mutated_size);
				}

			}else if (t_exit_stat == TRG_EX_TMOUT){

				if (!tm_perfcheck_prev && save_soft_crash){
					soft_crashes++;
					save_rep(1,(u8*)mutated_input,mutated_size);
				}

			}else {
				total_crashes++;
				should_store=1;
				last_crash_mut=mut_op_used;
				save_rep(0,(u8*)mutated_input,mutated_size);
			}

#ifdef RECORD_FEEDS
			if (net_mode){
				store_reset(should_store);
				should_store = 0;
			}
#endif

		}


#ifdef LIVE_STAT
		live_rep();
#endif

		/*
			Do Statistics about
			this input here
		*/

		switch (pm_mode){
			case 0:
				if (depth_grew){
					if (add_to_inputs){
						save_mutated_input(mutated_input,mutated_size);
					}
				}
				break;
			case 1:
			case 2:
				/*
					In contrast to max_depth which is the depth
					of the deepest tree, total_covered
					is the cumultive variable showing total
					number of nodes in all trees.
					However for saving inputs we have 2 options:
					1- we consider those
					with individual nodes growth like those
					with individual depth growth for the pm0

					2- We consider total_covered instead. This
					will save many more new inputs which can be
					a little excessive.

				*/
				if (invd_tree_nodes_grew){
					if (add_to_inputs){
						save_mutated_input(mutated_input,mutated_size);
					}
				}

				break;
		}

		/*
		if (total_covered > total_covered_sav){
			add_stat_entry();
		}
		*/


	}


	c=munmap(saved_input,alloc_size);
	if (c) zexit("generator: munmap()");
	c=munmap(mutated_input,alloc_size);
	if (c) zexit("generator: munmap()");


	return;
}

void adjust_timeout(){
	int i=0,c;
	void *data;
	FILE *f;
	int input_ind;
	size_t actual_size;
	u8 *p;
	struct stat st;
	struct timespec stime,etime;
	u64 stime_us,etime_us;
	u64 max_exec=0,exec_time;



	for (i=0;i<10;i++){
		input_ind = i%input_count;

		if (lstat(input_queue[input_ind].i_path,&st)==-1){
			zexit("adjust_timeout: stat");
		}

		actual_size = st.st_size;


		data = mmap(0,actual_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);


		if (data==MAP_FAILED ){
			zexit("adjust_timeout failed due to memory inaccessiblity");
		}
		f = fopen(input_queue[input_ind].i_path,"r");
		if (!f){
			zexit("adjust_timeout: open failed");
		}
		p = data;
		while((c=fgetc(f)) != -1){
			*p++ = c;
		}
		fclose(f);


		write_g_input(data,actual_size);
		clock_gettime(CLOCK_REALTIME,&stime);
		execute(0);
		clock_gettime(CLOCK_REALTIME,&etime);
		stime_us=stime.tv_sec*1000000 + stime.tv_nsec/1000;
		etime_us=etime.tv_sec*1000000 + etime.tv_nsec/1000;
		exec_time = etime_us- stime_us;
		printf("%d : %s : %luus\n",input_ind,input_queue[input_ind].i_path,exec_time);
		if (exec_time > MAX_TIMEOUT_VAL_INIT){
			zexit("Running target with input '%s' is too slow (>%lums).\n"
				  "\t Either change your arguments or remove this input and restart zharf."
				  ,input_queue[input_ind].i_path,MAX_TIMEOUT_VAL_INIT/1000);
		}
		if (exec_time > max_exec){
			max_exec=exec_time;
		}

		if (munmap(data,actual_size)){
			zexit("adjust_timeout(): munmap()");
		}
	}

	/*
		Add a little more time to tolerate
		execution time variances.
	*/

	max_exec+=(TOI_RATE)*(max_exec);

	if (max_exec > MAX_TIMEOUT_VAL_RUN)
		max_exec=MAX_TIMEOUT_VAL_RUN;

	active_timeout = max_exec;

	/*
		We don't want to take the opportunity of
		running more number of nodes from the
		target completely.
	*/
	if (active_timeout < MIN_TIMEOUT_VAL){
		active_timeout = MIN_TIMEOUT_VAL;
	}

	zrep("Chosen timeout: %lums",active_timeout/1000);

}
void do_post_process(){

	input_queue[queue_use_ind].passed = 1;

	switch (pm_mode){
		case 0:
			if (input_queue[queue_use_ind].prio == 0){
				if (input_queue[queue_use_ind].depth < LPSD_MAX_DEPTH){
					if (LPSD_queue[input_queue[queue_use_ind].depth] > MLPSD_ALLOWED){
						if (LPSD_queue_wait[input_queue[queue_use_ind].depth] < MLPSD_ALLOWED){
							LPSD_queue_wait[input_queue[queue_use_ind].depth]++;
						}else{
							LPSD_queue_wait[input_queue[queue_use_ind].depth]=0;
							LPSD_queue[input_queue[queue_use_ind].depth]=0;
						}
					}
				}
			}

			break;
		case 1:
			if (input_queue[queue_use_ind].prio == 0){
				if (input_queue[queue_use_ind].total_blocks < LPSC_MAX_NODES){
					if (LPSC_queue[input_queue[queue_use_ind].total_blocks] > MLPSC_ALLOWED){
						if (LPSC_queue_wait[input_queue[queue_use_ind].total_blocks] < MLPSC_ALLOWED){
							LPSC_queue_wait[input_queue[queue_use_ind].total_blocks]++;
						}else{
							LPSC_queue_wait[input_queue[queue_use_ind].total_blocks]=0;
							LPSC_queue[input_queue[queue_use_ind].total_blocks]=0;
						}
					}
				}
			}
			break;

		case 2:

			break;

	}

}

/*
	We don't return from this function
	until fuzer is closed by user or an irrecoverable
	error happens.
*/
void zharf_start(){
	int t_exit_stat;
	int i;

	shared_trace_tree = shm_adr + LOCK_DELTA + PROT_VARS_DELTA;
	if (!shared_trace_tree){
		zexit("trace_tree");
	}
	zrep("tree at: %016lx",shared_trace_tree);

	for (i=0;i<input_count;i++){

		if (file_feed){
			prepare_file_feed(input_queue[i].i_path);
		}else{

			modify_input(input_queue[i].i_path);
		}


		/*
				execute for this input and see
				it works as expected or not
				it shouldn't crash the target
				Input is fed only for regular mode.
				Target is then terminated.
				For net mode input is not sent.
		*/

		t_exit_stat = execute(1);
		if (t_exit_stat==-1){
			zexit("Unexpected state in target execution");
		}
		if (t_exit_stat==TRG_EX_CRASH){
			zexit("Input %s crashed target.",input_queue[i].i_path);
		}
		if (net_mode && t_exit_stat == TRG_EX_NORMAL){
			zexit("Target does not stay alive to handle connections.");
		}
		if (!net_mode){
			eval_tree(&input_queue[i]);
			/*
				Just add to local blocks
				don't need to check return value
			*/
			coverage_changes();

		}
		zrep("Checked %s",input_queue[i].i_path);
	}

	if (coverage_only){
		zrep("Coverage with this input set: %lf",(double)total_covered/_st_indp);
		znormal_exit();
	}
	if (user_timeout==-1){
		if (!net_mode){
			adjust_timeout();
		}
	}else{
		active_timeout = user_timeout;
	}

	if (cov_show_only){
		zrep("Total covered basic blocks: %lu",total_covered);
		znormal_exit();
	}

	active_timeout_sav = active_timeout;

	while(1){

		next_queue_ind();

		zharf_generate();
		/*
			at this point new inputs might have been added
			to the queue by the generator.
		*/
		do_post_process();

	}

}

void load_dictionary(){

	int kwp=0;
	FILE *f;
	char kw_line[2*DICT_MAX_KW_SIZE];

	f=fopen(dict_file,"r");

	if (!f){
		zexit("Loading dictionary failed");
	}

	while (fgets(kw_line,2*DICT_MAX_KW_SIZE,f)){
		if (dict_kw_count == DICT_MAX_KEYWORDS){
			zexit("Too many keywords in dictionary. Max %d",DICT_MAX_KEYWORDS);
		}
		if (kw_line[0]=='\n')
			continue;

		dict_kws[dict_kw_count]=calloc(DICT_MAX_KW_SIZE+1,1);

		if (!dict_kws[dict_kw_count]){
			zexit("calloc");
		}

		kwp=0;
		while (kw_line[kwp]!='\n'){
			if (kwp==DICT_MAX_KW_SIZE){
				kw_line[strlen(kw_line)-1]=0;
				zexit("Keyword '%s...' is too long.",kw_line);
			}
			dict_kws[dict_kw_count][kwp]=kw_line[kwp];
			kwp++;
		}
		dict_kw_count++;
	}


	fclose(f);



}
void print_banner(){

	printf(CRED"--------------------<[ ZHARF ]>------------------\n"CNORM);
	printf(CGREEN"*\t\t\t\t\t\t*\n"CNORM);
	printf(CGREEN"*\t\t   VERSION 1.1   \t\t*\n"CNORM);
	printf(CGREEN"*\t\t\t\t\t\t*\n"CNORM);
	printf(CGREEN"*\t\tBy Sirus Shahini\t\t*\n"CNORM);
	printf(CGREEN"*************************************************\n\n"CNORM);
}


void init_net_essentials(){
	init_socket();
	inet_pton(AF_INET,target_ip,&(target_saddr.sin_addr));
	target_saddr.sin_family = AF_INET;
    target_saddr.sin_port = htons(tcp_port);
}
void read_to_mem(void *data,char *path){
	FILE *f;
	int c;
	u8* p=data;

	f=fopen(path,"r");
	if (!f){
		zexit("read_to_mem()");
	}

	while ((c=fgetc(f))!=-1){
		*p++ = c;

	}

	fclose(f);
}

void pin_to_cpu(){
	u8 cpu_count = 0;
	FILE *stat_file;
	char line[1024];
	struct stat st;
	DIR *d;
	struct dirent* entry;
	u8 *cpus;
	int i;
	cpu_set_t free_cpu;

	stat_file=fopen("/proc/stat","r");
	if (!stat_file){
		zexit("pin_to_cpu(): fopen");
	}

	while (fgets(line,sizeof(line),stat_file)){
		if (!strncmp(line,"cpu",3) && isdigit(line[3]))
			cpu_count++;
	}

	fclose(stat_file);

	zrep("Found %d CPU cores in your machine",cpu_count);

	cpus = malloc(cpu_count);
	memset(cpus,0,cpu_count);

	d = opendir("/proc");
	while ((entry=readdir(d))!=NULL){
		char p_path[MAX_PATH];
		char *proc_file;
		char *cpu_aff_line;
		int cpu_num;
		int alloc_size = 4096;

		if (!isdigit(entry->d_name[0])) continue;

		sprintf(p_path,"/proc/%s/status",entry->d_name);

		if (lstat(p_path,&st)<0){
			/* Process has already died */
			continue;
		}
		if (st.st_size > 0){
			/*
				files in proc file system
				usually don't have a size stamp
				So we probably won't be here
			*/
			alloc_size = st.st_size;
		}

		proc_file = mmap(0,alloc_size,PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);
		if (proc_file==MAP_FAILED){
			zexit("pin_to_cpu(): mmap");
		}
		memset(proc_file,0,alloc_size);

		read_to_mem(proc_file,p_path);

		if (!strstr(proc_file,"VmSize")) continue;

		cpu_aff_line = strstr(proc_file,"Cpus_allowed_list");

		*(strchr(cpu_aff_line,'\n')+1) = 0;

		if (strchr(cpu_aff_line,'-') || strchr(cpu_aff_line,',')) continue;

		if (sscanf(cpu_aff_line+strlen("Cpus_allowed_list:\t"),"%u",&cpu_num)>0){
			cpus[cpu_num] = 1;
		}

		if (munmap(proc_file,alloc_size)){
			zexit("pin_to_cpu(): munmap");
		}
	}



	for (i=0;i<cpu_count;i++){
		if (!cpus[i]) break;
	}

	if (i==cpu_count){
		zwarn("No free CPU. You are advised against running multiple instances of zharf.");
	}

	/*
		There's at leat one free core
	*/

	CPU_ZERO(&free_cpu);
	CPU_SET(i,&free_cpu);
	sched_setaffinity(0,sizeof(cpu_set_t),&free_cpu);

	attached_core = i;
	zrep("Attached zharf to cpu%d",i);

	free(cpus);
	closedir(d);

}
#ifdef _DEBUG
/*
	Developer only
*/
void test_muts(){
	u8 buf_test[256];
	u8 buf_test_save[64];
	int i;
	size_t dummy;

	memset(mut_map+2,1,5);
	printf("> %02x\n",check_interesting(2,0xffffFFFF));
	memset(mut_map+2,0,5);
	mut_map[8]=1;
	for(i=0;i<256;i++){
		buf_test_save[i] = RU8(255);
	}
	printf("Init: \n");
	dump_hex(buf_test_save,64,-1,-1);
	//char buf[256];
	//printf("%s\n",(char*)show_data(buf,buf_test_save,16,2,2));
	//exit(0);
	while(1){
		u8 mut_op = 16+RU8(10);
		printf("%d\n",mut_op);
		size_t m_start,m_end,mutated_size,actual_size=0;;
		void *mutated_input = buf_test;
		mutated_size=65;
		memcpy(buf_test,buf_test_save,64);
		switch (mut_op){
			case 17:
				mut_rand_flip(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 18:
				mut_over_rand_8_int(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 19:
				mut_over_rand_16_int(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+2;
				break;
			case 20:
				mut_over_rand_32_int(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+3;
				break;
			case 21:
				mut_rand_8_add_sub(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 22:
				mut_rand_16_add_sub(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+2;
				break;
			case 23:
				mut_rand_32_add_sub(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+3;
				break;
			case 24:
				mut_rand_8_byte(mutated_input,mutated_size,mut_op,&m_start);
				m_end=m_start+1;
				break;
			case 25:
				mut_insert_const(mutated_input,mutated_size,mut_op,&m_start,&m_end,&mutated_size);

				break;
			case 26:
				mut_ow_const(mutated_input,mutated_size,mut_op,&m_start);
		}

		//mut_insert_const(mutated_input,mutated_size,mut_op,&m_start,&mutated_size);
		dummy=m_start;
		dump_hex(buf_test,64,dummy,dummy+1);
		fgetc(stdin);
	}

}
#endif

void dir_check_create(char *p){
	if (access(p,F_OK))
		if (mkdir(p,0775))
			zexit("mkdir() failed: %s",strerror(errno));
}
int main(int argc,char **argv){
	int opt;
	char *tmp_s=0;
	char tmp_path[1024];
	char gbuf[255];
	FILE *fgov;
#ifdef LIVE_STAT
	FILE *frep;
	char _sname[1024];
#endif
    struct sigaction sig_act;


	_st_bl=0;
	_st_indp=0;
	_st_nes=0;

	feed_file_path = 0;
	output_dir=0;
	input_dir=0;
	file_feed = 0;
	queue_ind = 0;
	queue_use_ind = -1;
	opterr = 0; // getopt won't show error msg, we handle errors
	/*
		Short options suffice for our case
		hence getopt instead of getopt_long

		Release note: Please don't run the fuzzer
		with developer-only options.

	*/
	while ((opt = getopt (argc, argv, "+i:o:n:df:mcp:gB:t:esak:ry:h")) != -1)
	switch (opt)
	{
		case 'd':
			debug_mode=1;
        	break;
		case 'i':
			if (input_dir)
				zexit("Multiple input directories found in args");
			input_dir=optarg;
        	break;
		case 'o':
			if (output_dir)
				zexit("Multiple output directories found in args");
			output_dir=optarg;
			break;
		case 'f':
			file_feed = 1;
			feed_file_path = optarg;
			break;
		case 'n':
			net_mode = 1;
			tmp_s = optarg;
			break;
		case 'm':
			target_mult_threaded = 1;
			break;
		case 'c':
			enable_custom_cleanup = 1;
			break;
		case 'p':
			pm_str = optarg;
			break;
		case 'g':
			coverage_only = 1;
			use_term_gui = 0;
			break;
		case 'B':
			_st_indp = 0;
			sscanf(optarg,"%lu",&_st_indp);
			break;
		case 'T':
			_st_bl = 0;
			sscanf(optarg,"%lu",&_st_bl);
			break;
		case 'N':
			_st_nes = 0;
			sscanf(optarg,"%lu",&_st_nes);
			break;
		case 't':
			sscanf(optarg,"%lu",&user_timeout);
			break;
		case 'e':
			cov_show_only = 1;
			use_term_gui =0;
			break;
		case 's':
			save_soft_crash=1;
			break;
		case 'a':
			add_to_inputs = 1;
			break;
		case 'k':
			sscanf(optarg,"%d",&perf_check_req);
			break;
		case 'r':
			should_store_graph=1;
			break;
		case 'y':
			dict_file = optarg;
			break;
		case 'h':
			print_usage();
			break;
      	case '?':
      		if (isprint(optopt))
      			printf("Unsupported option: %c\n",optopt);
      		print_usage();
	}
	if (debug_mode){
		zexit("Debug mode: Developer only");
		debug_memory((void *)0x00007efde8863000);
		return 0;
	}
	if (optind==argc || input_dir==0 || output_dir==0){
		print_usage();
	}
	print_banner();

	if (access(input_dir,F_OK) || access(output_dir,F_OK)){
		zexit("input/output path not accessible");
	}

	if (_st_indp<1){
		if (coverage_only)
			zexit("User didn't provide total number of basic blocks (can be obtained from zcc)");
		else
			zrep("User didn't provide total number of basic blocks (can be obtained from zcc)");
	}

	if (perf_check_req > 2 || perf_check_req < 0){
		zexit("Invalid mode of performance check. (use 0,1,2. default:0)");
	}

	/*
		For netwrok mode performance check
		won't have mmuch effect since we work
		with RECV_TIMEOUT.
		The only time active_timeout is used in
		that mode is for respawning a dead server.
		I prefer not to change socket timeout dynamically.
	*/
	perf_check = perf_check_req;

	if (user_timeout!=-1){
		user_timeout*=1000; //mili to micro
		if (user_timeout > MAX_TIMEOUT_VAL_RUN || user_timeout < MIN_TIMEOUT_VAL){
			zexit("Invalid timeout value.");
		}else{
			//active_timeout = user_timeout;
		}
	}

	zrep("Running as %d",getpid());
	target_path=argv[optind];
	target_argv=&argv[optind];

	if(access(target_path,F_OK)){
		zexit("Given target program is not accessible.");
	}

	if (net_mode){
		sscanf(tmp_s,"%d",&tcp_port);
		if (tcp_port <=0)
			zexit("Watch your port number input");
		init_net_essentials();
	}
	zrep("Fuzzing: '%s'",target_path);
	zrep("Reading input from '%s'",input_dir);
	zrep("Writing results in '%s'",output_dir);
	if (net_mode){
		zrep("TCP mode is active, using port number %d",tcp_port);
	}
	if (target_mult_threaded){
		zrep("Got -m switch. Depth comparison will be disabled.");
	}
	dev_null = open("/dev/null",O_RDWR);
	read_inputs();



	zrep("Found total %u inputs",input_count);
	if (queue_ind==0) {
		zexit("No input file");
	}

	signal(SIGINT,int_handler);
	signal(SIGALRM,target_timeout);
	signal(SIGPIPE,pipe_handler);

	sig_act.sa_flags=SA_SIGINFO;
	sig_act.sa_sigaction = &sigf_handler;
	sigaction(SIGSEGV, (const struct sigaction *)&sig_act,NULL);



	prepare_input_feed();

	/*
		Priority mode check here
	*/
	if (pm_str){
		if (strcmp(pm_str,"TDF")==0){
			if (target_mult_threaded){
				zexit("A multithreaded program cannot be fuzzed in this "
						"priority model. Change either -p or -m options.");
			}
			pm_mode = 0;
		}else if (strcmp(pm_str,"TNF")==0){
			pm_mode = 1;
		}else if (strcmp(pm_str,"TNS")==0){
			pm_mode = 2;
		}else{
			zexit("Priority model not supported. Watch your -p option");
		}

		zrep("Requested priority model: %s",pm_str);
	}else{
		zrep("Priority model set to default as TDF");
		pm_str = DEFAULT_PM_STR;
	}

	if (_st_bl)
		zrep("Total number of basic blocks: %lu",_st_bl);
	else
		zrep("Total number of basic blocks: Not provided");

	if (user_timeout!=-1){
		zrep("User requested timeout: %lums",user_timeout/1000);
	}

	zrep("Performance-check mode: %d",perf_check);

	if (should_store_graph){
		zrep("Graphs will be stored per user request.");
	}

	if (lpq_balance){
		zrep("LPQ Balance mode 1 in effect.");
	}else{
		zrep("LPQ Balance mode 0 in effect.");
	}

	if (dict_file){
		zrep("Using dictionary file: %s",dict_file);
		load_dictionary();
	}

	pin_to_cpu();

	/*
		Run the starter and initialize it
	*/
	starter_id = 0;


	run_starter();

	if (coverage_only){
		zrep("Coverage mode requested: will only run one iteration and exit.");

	}

	time(&start_time);
	srand(start_time);

#ifdef LIVE_STAT
	frep=fopen(LIVE_REP_FILE,"w");
	if (!frep){
		zexit("Creating live stat file failed");
	}
	strcpy(_sname,target_path);
	fprintf(frep,"%lu\n%s\n%lu\n%lu\n%lu\n",
				 start_time,basename(_sname),_st_bl,_st_indp,_st_nes);
	fclose(frep);
#endif
	if (net_mode)
		strcpy(current_stat,CGREEN"NORMAL [Network Mode]"CNORM);
	else
		strcpy(current_stat,CGREEN"NORMAL"CNORM);

	fgov=fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor","r");
	if (!fgov)
		zexit("fopen(): CPU governer core 0");
	fgets(gbuf,12,fgov);
	if (strcmp(gbuf,"performance"))
		zwarn("Fuzzer works better in 'performance' mode of CPUFreq governor.");
	clear_warn();
	fclose(fgov);

/************ PM modes initializations here ****************/

	switch(pm_mode){
		case 0:
			memset(LPSD_queue,0,sizeof(LPSD_queue));
			memset(LPSD_queue_wait,0,sizeof(LPSD_queue));
			break;
		case 1:
			/*
				This is only allcoated once and lives
				until fuzzer termination. No need to unmap
			*/
			LPSC_queue=mmap(0,LPSC_MAX_NODES,PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);
			if (LPSC_queue==MAP_FAILED){
				zexit("mmap()");
			}
			memset(LPSC_queue,0,LPSC_MAX_NODES);

			LPSC_queue_wait=mmap(0,LPSC_MAX_NODES,PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1 , 0);
			if (LPSC_queue_wait==MAP_FAILED){
				zexit("mmap()");
			}
			memset(LPSC_queue_wait,0,LPSC_MAX_NODES);
			break;
		case 2:

			break;

	}


	zharf_init_state = 0;

	if (use_term_gui)
		printf(HC);

	/* Set up output directories */
	sprintf(tmp_path,"%s/q",output_dir);
	dir_check_create(tmp_path);
	sprintf(tmp_path,"%s/crashes",output_dir);
	dir_check_create(tmp_path);
	/*
		Fire up the fuzzer
	*/
	zharf_start();

	return 0;
}
