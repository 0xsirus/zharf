/*
	By Sirus Shahini
	~cyn
*/

#include "head.h"

#define AS_LINE_LIMIT (1<<12)
#define MAX_AS_RAND	(1<<16)
char zharf_dir[MAX_PATH];


//#define ALWAYS_SAVE_FLAGS

//#define SAVE_ALL_REGS

#ifdef ALWAYS_SAVE_FLAGS
#define FREGS_RSP_DELTA "88"
#else
#define FREGS_RSP_DELTA "72"
#endif

#ifdef SAVE_ALL_REGS
#define GREGS_RSP_DELTA "128"
#define GREGS_DELTA	"112"
#else
#define GREGS_RSP_DELTA "80"
#define GREGS_DELTA	"72"
#endif

#define XREGS_RSP_DELTA "256"

#define ZHARF_AS_PATH "/usr/local/zharf_helper/"

const char BACKUP_FREGS[] =		"\tlea -(0+"FREGS_RSP_DELTA")(%rsp),%rsp\n"
							 	"\tmov %rdi,0(%rsp)\n"
							 	"\tmov %rsi,8(%rsp)\n"
								"\tmov %rdx,16(%rsp)\n"
								"\tmov %rcx,24(%rsp)\n"
								"\tmov %r8,32(%rsp)\n"
								"\tmov %r9,40(%rsp)\n"
								"\tmov %r10,48(%rsp)\n"
								"\tmov %r11,56(%rsp)\n"
								"\tmov %rax,64(%rsp)\n"
#ifdef ALWAYS_SAVE_FLAGS
								"\tlahf\n"
								"\tseto %al\n"
								"\tmov %rax,72(%rsp)\n"
#endif
								;


const char BACKUP_GREGS[] =		"\tlea -(128+"GREGS_RSP_DELTA")(%rsp),%rsp\n"
							 	"\tmov %rax,0(%rsp)\n"
								"\tmov %rcx,8(%rsp)\n"
								"\tmov %rdx,16(%rsp)\n"
								"\tmov %rdi,24(%rsp)\n"
								"\tmov %rsi,32(%rsp)\n"
								"\tmov %r8,40(%rsp)\n"
								"\tmov %r9,48(%rsp)\n"
								"\tmov %r10,56(%rsp)\n"
								"\tmov %r11,64(%rsp)\n"
#ifdef SAVE_ALL_REGS
								"\tmov %rbx,72(%rsp)\n"
								"\tmov %r12,80(%rsp)\n"
								"\tmov %r13,88(%rsp)\n"
								"\tmov %r14,96(%rsp)\n"
								"\tmov %r15,104(%rsp)\n"
#endif
								"\tlahf\n"
								"\tseto %al\n"
								"\tmov %rax,"GREGS_DELTA"(%rsp)\n";

const char BACKUP_XREGS[] =	  "\tadd $-(0+"XREGS_RSP_DELTA"),%rsp\n"
							  "\tvmovdqu %xmm0,0(%rsp)\n"
							  "\tvmovdqu %xmm1,16(%rsp)\n"
							  "\tvmovdqu %xmm2,32(%rsp)\n"
							  "\tvmovdqu %xmm3,48(%rsp)\n"
							  "\tvmovdqu %xmm4,64(%rsp)\n"
							  "\tvmovdqu %xmm5,80(%rsp)\n"
							  "\tvmovdqu %xmm6,96(%rsp)\n"
							  "\tvmovdqu %xmm7,112(%rsp)\n"
							  "\tvmovdqu %xmm8,128(%rsp)\n"
							  "\tvmovdqu %xmm9,144(%rsp)\n"
							  "\tvmovdqu %xmm10,160(%rsp)\n"
							  "\tvmovdqu %xmm11,176(%rsp)\n"
							  "\tvmovdqu %xmm12,192(%rsp)\n"
							  "\tvmovdqu %xmm13,208(%rsp)\n"
							  "\tvmovdqu %xmm14,224(%rsp)\n"
							  "\tvmovdqu %xmm15,240(%rsp)\n";
//***************

const char RESTORE_FREGS[] = 	"\tmov 0(%rsp),%rdi\n"
								"\tmov 8(%rsp),%rsi\n"
								"\tmov 16(%rsp),%rdx\n"
								"\tmov 24(%rsp),%rcx\n"
								"\tmov 32(%rsp),%r8\n"
								"\tmov 40(%rsp),%r9\n"
								"\tmov 48(%rsp),%r10\n"
								"\tmov 56(%rsp),%r11\n"
								"\tmov 64(%rsp),%rax\n"
#ifdef ALWAYS_SAVE_FLAGS
								"\tmov 72(%rsp),%rax\n"
								"\tadd $127,%al\n"
								"\tsahf\n"
#endif
								"\tlea (0+"FREGS_RSP_DELTA")(%rsp),%rsp\n"

								;

const char RESTORE_GREGS[] = 	"\tmov "GREGS_DELTA"(%rsp),%rax\n"
								"\tadd $127,%al\n"
								"\tsahf\n"
								"\tmov 0(%rsp),%rax\n"
								"\tmov 8(%rsp),%rcx\n"
								"\tmov 16(%rsp),%rdx\n"
								"\tmov 24(%rsp),%rdi\n"
								"\tmov 32(%rsp),%rsi\n"
								"\tmov 40(%rsp),%r8\n"
								"\tmov 48(%rsp),%r9\n"
								"\tmov 56(%rsp),%r10\n"
								"\tmov 64(%rsp),%r11\n"
#ifdef SAVE_ALL_REGS
								"\tmov 72(%rsp),%rbx\n"
								"\tmov 80(%rsp),%r12\n"
								"\tmov 88(%rsp),%r13\n"
								"\tmov 96(%rsp),%r14\n"
								"\tmov 104(%rsp),%r15\n"
#endif
								"\tlea (128+"GREGS_RSP_DELTA")(%rsp),%rsp\n";


/*
	Floating point registers
*/

const char RESTORE_XREGS[] =  "\tmovdqu 0(%rsp),%xmm0\n"
							  "\tmovdqu 16(%rsp),%xmm1\n"
							  "\tmovdqu 32(%rsp),%xmm2\n"
							  "\tmovdqu 48(%rsp),%xmm3\n"
							  "\tmovdqu 64(%rsp),%xmm4\n"
							  "\tmovdqu 80(%rsp),%xmm5\n"
							  "\tmovdqu 96(%rsp),%xmm6\n"
							  "\tmovdqu 112(%rsp),%xmm7\n"
							  "\tmovdqu 128(%rsp),%xmm8\n"
							  "\tmovdqu 144(%rsp),%xmm9\n"
							  "\tmovdqu 160(%rsp),%xmm10\n"
							  "\tmovdqu 176(%rsp),%xmm11\n"
							  "\tmovdqu 192(%rsp),%xmm12\n"
							  "\tmovdqu 208(%rsp),%xmm13\n"
							  "\tmovdqu 224(%rsp),%xmm14\n"
							  "\tmovdqu 240(%rsp),%xmm15\n"
							  "\tlea (0+"XREGS_RSP_DELTA")(%rsp),%rsp\n";


u8 save_xregs = 0;
char tmp_as[255];
u32 as_i=0;
u8 count_bb=1;
u64 total_injects = 0;
u64 indp_blocks = 0;
u64 nested_blocks = 0;
u8 add_debug_symbols=1;
u8 add_optimization=1;

/*
	Marking does NOT work for inline funcitons.
*/
u8 mark_imp_funcs = 0;
/*
	Write the name of your marked
	functions here on function name
	per a char array.
	Example:
		{"function1","function2",...}
*/
char *important_funcs[] = {""};
int tot_marked=0;

#define EXTRA_FLAGS	12
float instrumentation_ratio = 1.0;

ID_SIZE global_id=1;

char hook_payload[] =
	"\tmov $0x%016lx,%%rdi\n"
	"\tmov $0x%02x,%%esi\n"
	"\tcall lib_zh_entry@PLT\n";

u8 debug_mode = 0;
u8 bridge_log = 0;

void zexit(char *fmt, ...){
	char err_format[2048];

	strcpy(err_format,CRED "[!]" CNORM " Bridge: ");
	strcat(err_format,fmt);
	strcat(err_format,"\n");
	va_list argp;
	va_start(argp,err_format);
	vprintf(err_format,argp);
	va_end(argp);

	exit(-1);
}
void zrep(char *fmt, ...){
	char msg_format[2048];


	strcpy(msg_format,CGREEN "[-]" CNORM " Bridge: ");
	strcat(msg_format,fmt);
	strcat(msg_format,"\n");
	va_list argp;
	va_start(argp,msg_format);
	vprintf(msg_format,argp);
	va_end(argp);
}
ID_SIZE next_id(){
	ID_SIZE new_id = 0xFFFFFFFFFFFFFF;
	new_id *= (rand()/(double)RAND_MAX);
	new_id++;
	return new_id;
}

#define get_spec_byte(id)	((u8)(id >> ID_SPEC_SHIFT*8))
#define get_node_type(id)	(get_spec_byte(id) & BLOCK_TYPE)
ID_SIZE inject_payload(FILE *f,u8 save_regs,ID_SIZE id,u8 mark){
	ID_SIZE new_id;
	BLOCK_INFO_SIZE block_spec=0;
	if (!id){
		new_id=	next_id();
		block_spec &= ~BLOCK_TYPE;
		indp_blocks++;

	}else{
		block_spec |= BLOCK_TYPE;
		new_id = id;
		nested_blocks++;

	}

	if (mark){
		block_spec |= BLOCK_MARKED;
	}

	fputs("\n/* Zharf payload start */\n",f);
	if (save_regs==1) {
		fputs(BACKUP_GREGS,f);
		if (save_xregs){
			fputs(BACKUP_XREGS,f);
		}
	}else if(save_regs==2){
		fputs(BACKUP_FREGS,f);
	}else{
		zexit("Invalid register operation status");
	}

	fprintf(f,hook_payload,new_id,block_spec);
	if (save_regs==1) {
		if (save_xregs){
			fputs(RESTORE_XREGS,f);
		}
		fputs(RESTORE_GREGS,f);
	}else if(save_regs==2){
		fputs(RESTORE_FREGS,f);
	}else{
		zexit("Invalid register operation status");
	}
	fputs("/* Zharf payload end */\n\n",f);
	if (bridge_log)
		printf("[-] Instrumented with ID %016lx\n",new_id);
	total_injects++;
	return new_id;
}


void instrument_assembly(char *input_as){
	FILE *as_in;
	FILE *as_out;
	u8 good_section = 0;
	u8 inject_awaiting=0;
	u8 save_regs=0;
	u8 use_last_id=0,mark_used=0;
	u8 arc_64 = 1;
	u8 att_syntax = 1;
	u8 no_app = 1;
	u8 barrier_free = 1;
	u8 instrument_unconditioned = 0;
	u8 nested_barrier_free=1;
	ID_SIZE last_id=0;
	u8 mark_block=0;
	u8 parent_instrumented=0;

	char as_line[AS_LINE_LIMIT];
	char cmd[1064];

	/* save as file for debug */
	if (debug_mode){
		sprintf(cmd,"cp %s ./as_file.s",input_as);
		system(cmd);
	}


	if(bridge_log)
		zrep("openning %s\n",input_as);
	as_in = fopen(input_as,"r");
	if (as_in ==0){
		zexit("fopen(): input as");
	}
	as_out = fopen(tmp_as,"w");
	if (as_out ==0){
		zexit("fopen(): output as");
	}

	while (fgets(as_line,AS_LINE_LIMIT,as_in)){

		if (instrument_unconditioned  ||
			(inject_awaiting && good_section && arc_64 && att_syntax
			&& no_app && as_line[0]=='\t' && isalpha(as_line[1]))
			){

				if (use_last_id && parent_instrumented){
					last_id = inject_payload(as_out,save_regs,last_id,mark_block);
				}
				else{
					if( RU8(100) <= (u8)(instrumentation_ratio*100)){
						parent_instrumented = 1;

						if (mark_block){
							if (mark_used)
								mark_block=0;
						}
						last_id = inject_payload(as_out,save_regs,0,mark_block);

						if (mark_block)
							mark_used=1;

						nested_barrier_free = 1;

					}else{
						parent_instrumented = 0;
					}


				}
				inject_awaiting = 0;


		}

		instrument_unconditioned = 0;

		fputs(as_line,as_out);

		if (good_section && !strncmp(as_line,"\t.p2align",strlen("\t.p2align")) &&
			isdigit(as_line[10]) && as_line[11]=='\n'){
			barrier_free = 0;


		}
		if ( !strncmp(as_line,"\t.text",strlen("\t.text")) ||
			 !strncmp(as_line,"\t.section\t.text",strlen("\t.section\t.text"))
		){
			good_section=1;
			continue;
		}
		if ( !strncmp(as_line,"\t.bss",strlen("\t.bss")) ||
			 !strncmp(as_line,"\t.data",strlen("\t.data")) ||
			 !strncmp(as_line,"\t.section\t",strlen("\t.section\t")) ||
			 !strncmp(as_line,"\t.section ",strlen("\t.section "))
		){
			good_section=0;
			continue;
		}

		if ( strstr(as_line,".code32") ){
			/* We disregard 32 bit binaries */
			arc_64 = 0;
			continue;
		}
		if ( strstr(as_line,".code64") ){
			arc_64 = 1;
		}

		if ( strstr(as_line,".intel_syntax") ){
			/* not interested */
			att_syntax = 0;
			continue;
		}
		if ( strstr(as_line,".att_syntax") ){
			att_syntax = 1;
		}

		if ( strstr(as_line,"#APP") ){
			no_app = 0;
			continue;
		}
		if ( strstr(as_line,"#NO_APP") ){
			no_app = 1;
		}

		/*
			New line and still not good for instrumentation?
		*/
		if (!good_section || !arc_64 || !att_syntax || !no_app ||
			as_line[0]=='#' || as_line[0]==' '){

			continue;
		}

		if (!save_xregs){
			/*
				TODO: Register saving can be much further
				optimized. Needs much more work though.
			*/
			if (strstr(as_line,"xmm")){
				save_xregs=1;
			}
		}
		if (as_line[0]=='\t'){
			/*
				Manage instrucitons
			*/
			if (as_line[1]=='j' && as_line[2]!='m'){
				instrument_unconditioned = 1;
				inject_awaiting = 1;
				save_regs = 1;
				use_last_id=0;
			}else if ( strstr(as_line,"\tcall") ){
				if (nested_barrier_free ){
					inject_awaiting = 1;
					save_regs = 1;
					use_last_id=1;
					instrument_unconditioned = 1;
				}
			}
			/*
				else other instructions
				We're done with this line
			*/
			continue;
		}

		/*
			Are we after Any label here?
		*/
		if (strstr(as_line,":")){
			if (as_line[0]=='.'){
				if (isdigit(as_line[2])){
					if (!barrier_free){
						barrier_free=1;
						/*
							No nested block here when the parent
							block is going to be excluded
						*/
						nested_barrier_free = 0;
					}else{
						inject_awaiting = 1;
						save_regs = 1;
						use_last_id=0;
					}
					continue;
				}
				/*
					else other file labels we are not
					interested in

				*/
			}
			else{
				int i;
				char candidate_line[255];
				int candidate_len = strstr(as_line,":") - as_line;


				memcpy(candidate_line,as_line,candidate_len);
				candidate_line[candidate_len]=0;
				save_xregs=0;
				inject_awaiting = 1;
				save_regs = 2;
				use_last_id=0;
				if (mark_imp_funcs){
					for (i=0;i<sizeof(important_funcs)/8;i++){
						if (!strcmp(candidate_line,important_funcs[i])){
							mark_block=1;
							mark_used =0;
							tot_marked++;
							break;
						}
					}
				}

				continue;

			}
		}


	}

	fclose(as_in);
	fclose(as_out);


	if (debug_mode){
		sprintf(cmd,"cp %s ./as_file_out.s",tmp_as);
		system(cmd);
	}
}

void rep_input_args(char **argv,int count){
	int i=0;
	printf("[-] In %s\n",argv[0]);
	for (i=0;i<count;i++){
		printf("\targ: %s\n",argv[i]);
	}
}
void rep_bridge_args(char **argv,int count){
	int i=0;
	if (count == 0){
		return ;
	}
	printf("[-] Run %s\n",argv[0]);
	for (i=0;i<count;i++){
		printf("\targ: %s\n",argv[i]);
	}
}
void store_count(char *path,u64 count){
	FILE *cf;
	char line[255];
	u64 n=0;

	if (access(path,F_OK) == 0){
		cf = fopen(path,"r+");
	}else{
		cf = fopen(path,"w+");
	}

	if (!cf){
		zexit("fopen: %s",strerror(errno));
	}
	line[0]=0;
	fgets(line,254,cf);
	if (line[0]){
		sscanf(line,"%lu",&n);
	}
	n+=count;
	fseek(cf,0,0);
	sprintf(line,"%lu\n",n);
	fwrite(line,1,strlen(line),cf);
	fclose(cf);

}

int main(int argc, char** argv) {
	char **argv_bridge;
	int i;
	int ar_index = 0;
	char lzh_arg[1064];
	struct timespec stime;
	u8 req_operation = 0;
	char *r_s;

	/*
		We consider the simplest case for now.
		user has ran:
		zcc prog.c

	*/

	if (argc<2){
		zexit("Wrong arguments");
	}

	if ((r_s=getenv("ZCC_RATIO"))){
		sscanf(r_s,"%f",&instrumentation_ratio);
	}

	if (instrumentation_ratio > 1){
		zexit("Invalid ratio");
	}

	clock_gettime(CLOCK_REALTIME,&stime);
	srand(stime.tv_nsec);

	if (bridge_log)
  		rep_input_args(argv,argc);

	argv_bridge = calloc((argc + EXTRA_FLAGS) * 8,1);
	//getcwd(zharf_dir,MAX_PATH);
	strcpy(zharf_dir,argv[0]);
	strcpy(zharf_dir , dirname(zharf_dir));
	if (strstr(argv[0],"zcc")){
		/*
			Compile
		*/
		if(bridge_log)
			zrep("Stage 1; compiling \n");
		if (getenv("BRG_NOOPT"))
			add_optimization=0;

	  	argv_bridge[ar_index++] = "gcc";
	  	for (i=1;i<argc;i++){
			argv_bridge[ar_index++] = argv[i];
		}

	  	/*
	  		Set reference directory to
	  		the directory which contains
	  		our as
	  	*/

	  	argv_bridge[ar_index++]="-B";
	  	if (!access(ZHARF_AS_PATH, F_OK))
	  		argv_bridge[ar_index++]=ZHARF_AS_PATH;
	  	else
	  		argv_bridge[ar_index++]=zharf_dir;
	  	/*
	  		Pass our library
	  	*/
	  	strcpy(lzh_arg,"-L ");
	  	strcat(lzh_arg,zharf_dir);
	  	strcat(lzh_arg,"/");
	  	argv_bridge[ar_index++] = lzh_arg;
	  	argv_bridge[ar_index++] = "-lzh";

	  	if (add_debug_symbols){
	  		argv_bridge[ar_index++] = "-g";
	  	}

	  	if (add_optimization){
	  		argv_bridge[ar_index++] = "-O3";
	  		/*
	  			Unrolling loops increases the
	  			number of basic blocks which is
	  			probably bad for our setup with
	  			extensive library code
	  		*/
	  		//argv_bridge[ar_index++] = "-funroll-loops";
	  	}

	}else if(strstr(argv[0],"as")){
		req_operation = 1;
		/*
			Inject our instrumentation payload
			pass to system assembler
		*/
		if(bridge_log)
			zrep("Stage 2; assembling \n");
		if (getenv("BRG_DEBUG"))
			debug_mode=1;

		argv_bridge[ar_index++] = "as";
	  	for (i=1;i<argc-1;i++){
			argv_bridge[ar_index++] = argv[i];
		}
		clock_gettime(CLOCK_REALTIME,&stime);
		as_i = MAX_AS_RAND * (rand()/(double)RAND_MAX);
		sprintf(tmp_as,"/tmp/zharf_tmp_%u.%lu.s",as_i,(u64)stime.tv_nsec);
		argv_bridge[ar_index++] = tmp_as;

		instrument_assembly(argv[argc-1]);

		printf("\n" CGREEN "zharf-zcc By Sirus Shahini\n" CNORM);
		zrep("Inserted payload to %lu addresses",total_injects);
		zrep("%lu Independent blocks and %lu nested blocks and %d marked blocks\n",
			indp_blocks,nested_blocks,tot_marked);
		if (count_bb){
			store_count("/tmp/zharf_count",total_injects);
			store_count("/tmp/zharf_indp",indp_blocks);
			store_count("/tmp/zharf_nested",nested_blocks);
			//zrep("Total %lu",n);
		}

	}else{
		zexit("Unknown state");
	}

  	if (bridge_log)
		rep_bridge_args(argv_bridge,ar_index);


	if (req_operation==1 && !debug_mode){
		int id=fork();
		int estat;
		if (id<0){
			zexit("fork failed");
		}
		if (id==0){
			execvp(argv_bridge[0], (char**)argv_bridge);
			zexit("Run failed\n");
		}
		if (waitpid(id,&estat,0)<0){
			zexit("waitpid failed");
		}
		unlink(tmp_as);
		return WEXITSTATUS(estat);
	}else{

		execvp(argv_bridge[0], (char**)argv_bridge);
		zexit("Run failed\n");
	}

	return 0;

}
