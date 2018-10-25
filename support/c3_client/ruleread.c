#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ruleread.h"
#include "util.h"
#include "alloc.h"


struct __rulereader{
	FILE *file;
	char **file_path;
	size_t file_no;
	size_t file_index;
	size_t line_no;
};


static inline size_t strstrim(char * str)
{
	//size_t i;
	//size_t endi;
	
	char * ptr;
	char *beginptr, * endptr;
	
	
	if(!str) return 0;

	for(ptr = str; *ptr != 0 ; ptr++){
		if(*str != '\t' && *str != ' ' && *str != '\r' && *str != '\n' ){
			break;
		}
	}

	beginptr = ptr;

	endptr = ptr;

	for(; *ptr != 0 ; ++ptr){
		if(*str != '\t' && *str != ' ' && *str != '\r' && *str != '\n'){
			endptr = ptr;
		}
	}

	if(*beginptr == 0){ 
		str[0] = 0;
		return 0;
	}

	if(*endptr){
		//endptr++;
	}

	memmove(str, beginptr, endptr - beginptr);
	str[endptr - beginptr] = '\0';

	return endptr - beginptr;
	
}

rulereader_t * rulereader_init(char **file, size_t file_no)
{
	rulereader_t * reader;
	char **filepath_list;
	unsigned int i;

	if(file_no == 0 || file_no > 1024){
		return NULL;
	}

	nn_assert(sizeof(struct in6_addr) == 16 && sizeof(struct in_addr) == 4);

	filepath_list = (char**)nn_alloc(sizeof(char **) * file_no, "filepath_list");
	nn_assert(filepath_list);
	memset(filepath_list, 0, sizeof(char **)* file_no);

	for(i = 0; i < file_no; i++){

		filepath_list[i] = (char*) nn_alloc(strlen(file[i]) + 2, "rule filepath");
		nn_assert(filepath_list[i]);
		strcpy(filepath_list[i], file[i]);
	}

	reader = (rulereader_t*) nn_alloc(sizeof(rulereader_t), "rulereader");

	nn_assert(reader);

	reader->file = NULL;
	reader->file_path = filepath_list;
	reader->file_no = file_no;
	reader->file_index = 0;

	return reader;

	/*
__err:

	if(filepath_list){
		for(i = 0; i < file_no; i++){
			nn_free( filepath_list[i]);
		}
		nn_free(filepath_list);
	}
	*/
}


//int rulereader_hasmore(rulereader_t * self);




int parse_type(const char * str)
{
	if(strcasecmp(str, "s4") == 0){
		return GRULE_BIG_TYPE_SIMPLE4;
	}else if(strcasecmp(str, "s6") == 0){
		return GRULE_BIG_TYPE_SIMPLE6;
	}else if(strcasecmp(str, "m4") == 0){
		return GRULE_BIG_TYPE_MASK4;
	}else if(strcasecmp(str, "m6") == 0){
		return GRULE_BIG_TYPE_MASK6;
	}else{
		return -1;
	}
}

int parse_ruletype(char * str, grule_type_t * ruletype)
{
	char * saved_ptr;
	char * ptr;

	grule_type_t old_type;
	
	ruletype->grule_type = 0; 


	old_type = *ruletype;
	
	ptr = strtok_r(str, "_", &saved_ptr);
	
	while( ptr ){

		if(strcasecmp(ptr, "sip") == 0 || strcasecmp(ptr, "s") == 0){
			ruletype->sip_flag = 1;
		}else if(strcasecmp(ptr, "dip") == 0 || strcasecmp(ptr, "d") == 0 ){
			ruletype->dip_flag = 1;
		}else if(strcasecmp(ptr, "sp") == 0 || strcasecmp(ptr, "sport") == 0 ){
			ruletype->sport_flag = 1;
		}else if(strcasecmp(ptr, "dp") == 0 || strcasecmp(ptr, "dport") == 0 ){
			ruletype->dport_flag = 1;
		}else if(strcasecmp(ptr, "msip") == 0 || strcasecmp(ptr, "ms") == 0){
			ruletype->sipmsk_flag= 1;
		}else if(strcasecmp(ptr, "mdip") == 0 || strcasecmp(ptr, "md") == 0 ){
			ruletype->dipmsk_flag= 1;
		}else if(strcasecmp(ptr, "msport") == 0 || strcasecmp(ptr, "msp") == 0){
			ruletype->spmsk_flag= 1;
		}else if(strcasecmp(ptr, "mdport") == 0 || strcasecmp(ptr, "mdp") == 0 ){
			ruletype->dpmsk_flag= 1;
		}else if(strcasecmp(ptr, "proto") == 0 || strcasecmp(ptr, "p") == 0){
			ruletype->proto_flag= 1;
		}else if(strcasecmp(ptr, "mproto") == 0 || strcasecmp(ptr, "mp") == 0 ) {
			ruletype->pmsk_flag= 1;
		}else{
			return -1;
		}

		if(ruletype->grule_type == old_type.grule_type){
			return -1;
		}

		old_type.grule_type = ruletype->grule_type;
		ptr = strtok_r(NULL, "_", &saved_ptr);
	}

	return 0;
	
}


#define RULE_DELEMITER "\r\n\t "

#if 0
#define RULE_SIP     0x0001
#define RULE_SIPMASK 0x0002
#define RULE_DIP     0x0004
#define RULE_DIPMASK 0x0008
#define RULE_SPORT   0x0010
#define RULE_SPMASK  0x0020
#define RULE_DPORT   0x0040
#define RULE_DPMASK  0x0080
#define RULE_PROTO   0x0100
#define RULE_PMASK   0x0200

#endif

static int parse_addr(int domain, const char * src, void * dst, int is_mask)
{
	int ret;

	unsigned long long  ip;
	ip6_addr_t ip6;
	int i;
	
	if(is_mask){
		if(strchr(src, '.') || strchr(src, ':')){
			ret = inet_pton(domain, src, dst);
			if(ret != 1) return -1;
		}else{
			ret = atoi(src);
			if(domain == AF_INET){
				if( ret < 0 || ret > 32){
					return -1;
				}
				ip = (1lu << 32) - (32 - (1lu << ret)); 
				memcpy(dst, &ip, sizeof(uint32_t));
			}else{
				if(ret < 0 || ret > 128){
					return -1;
				}
				memset(&ip6, 0, sizeof(ip6));

				for(i = 0; i < ret; i++){
					ip6.ip6_c[ i / 8 ] |= 1u << (8 -  ( i % 8 ) - 1);
				}
				
			}
			
		}
	}else{
		ret = inet_pton(domain, src, dst);
		if(ret != 1) return -1;
	}
	return 1;
}

static int parse_grule(const char * str, grule_t * rule)
{

	//char * typeptr;
	char * savedptr;
	char * ptr;
	int ret;
	int bigtype;
	int domain;
	int i;
	int flag;

	void * addr;

	// dev rule_scope srv_type durable action bigtype ruletype rule...
	grule_type_t grule_type;

	char buf[65536];

	strcpy(buf, str);

	rule->rule_id = 0;

	//dev

	ptr = strtok_r(buf, RULE_DELEMITER, &savedptr);

	if(ptr == NULL) return -1;

	if(strcasecmp(ptr, "S") == 0 || strcasecmp(ptr, "server")){
		
	}else if(strcasecmp(ptr, "S") == 0 || strcasecmp(ptr, "server")){

	}else if(strcasecmp(ptr, "S") == 0 || strcasecmp(ptr, "server")){

	}else{
		return -1;
	}

	// rule_scope

	ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
	if(ptr == NULL) return -1;
	
	ret = atoi(ptr);

	if(ret < 0 || ret >= (1 << 27)){
		return -1;
	}

	rule->rule_scope = ret;

	// service_type;
	ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
	if(ptr == NULL) return -1;
	
	ret = atoi(ptr);

	if(ret < 0 || ret > 255){
		return -1;
	}

	rule->srv_type = ret;

	//durable

	ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
	if(ptr == NULL) return -1;
	
	ret = atoi(ptr);

	if(ret != 0 && ret != 1){
		return -1;
	}

	rule->durable = ret;

	// action

	ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
	if(ptr == NULL) return -1;
	
	if(strcasecmp(ptr, "ADD") == 0 || strcasecmp(ptr, "1") == 0){
		rule->action = 1;
	}else if(strcasecmp(ptr, "DEL") == 0 || strcasecmp(ptr, "0") == 0 || strcasecmp(ptr, "DELETE") == 0){
		rule->action = 0;
	}else{
		return -1;
	}

	//bigtype
	ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);

	if(ptr == NULL) return -1;

	bigtype = parse_type( ptr );
	//rule->srv_type = 1;
	rule->big_type = bigtype;
	if(bigtype == GRULE_BIG_TYPE_SIMPLE4 || bigtype == GRULE_BIG_TYPE_MASK4){
		domain = AF_INET;
	}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6 || bigtype == GRULE_BIG_TYPE_MASK6){
		domain = AF_INET6;
	}else{
		return -1;
	}


	//ruletype
	ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
	if(ptr == NULL) return -1;

	ret = parse_ruletype(ptr, &grule_type);

	if(ret != 0) return -1;

	rule->rule_type = grule_type;
	

	flag = 1;

	

	for(i = 0; i < 10; i++, flag = flag << 1){

		if(!(grule_type.grule_type & flag)){
			continue;
		}

		ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);

		if(ptr == NULL){
			return -1;
		}

		switch(flag){
			case RULE_SIP     :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &rule->s4.sip;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &rule->s6.sip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.sip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.sip;	
				}
				ret = parse_addr(domain, ptr, addr, 0);
				if(ret != 1){
					return -1;
				}
				break;
			case RULE_SIPMASK :
				
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.;	
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					return -1;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.sip_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.sip_mask;	
				}
				ret = parse_addr(domain, ptr, addr, 1);
				if(ret != 1){
					return -1;
				}
				break;
			case RULE_DIP     :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &rule->s4.dip;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &rule->s6.dip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.dip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.dip;	
				}
				ret = parse_addr(domain, ptr, addr, 0);
				if(ret != 1){
					return -1;
				}
				break;
			case RULE_DIPMASK :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.dip;	
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.dip_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.dip_mask;	
				}
				ret = parse_addr(domain, ptr, addr, 1);
				if(ret != 1){
					return -1;
				}
				break;
			case RULE_SPORT   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &rule->s4.sport;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &rule->s6.sport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.sport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.sport;	
				}
				ret = atoi(ptr);
				if(ret < 0 || ret > 65535){
					return -1;
				}
				 ret = ntohs(ret);
				memcpy(addr, &ret, sizeof(uint16_t));
				break;
			case RULE_SPMASK  :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.sport_mask;	
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.sport;
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.sport_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.sport_mask;	
				}
				ret = atoi(ptr);
				if(ret < 0 || ret > 65535){
					return -1;
				}
				 ret = ntohs(ret);
				memcpy(addr, &ret, sizeof(uint16_t));
				break;
			case RULE_DPORT   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &rule->s4.dport;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &rule->s6.dport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.dport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.dport;	
				}
				ret = atoi(ptr);
				if(ret < 0 || ret > 65535){
					return -1;
				}
				 ret = ntohs(ret);
				memcpy(addr, &ret, sizeof(uint16_t));

				break;
			case RULE_DPMASK  :

				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.dport_mask;	
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.dport_mask;	
					return -1;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.dport_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.dport_mask;	
				}
				ret = atoi(ptr);
				if(ret < 0 || ret > 65535){
					return -1;
				}
				ret = ntohs(ret);
				memcpy(addr, &ret, sizeof(uint16_t));
				break;
			case RULE_PROTO   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &rule->s4.proto;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &rule->s6.proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.proto;	
				}
				ret = atoi(ptr);
				if(ret < 0 || ret > 255){
					return -1;
				}
				memcpy(addr, &ret, sizeof(char));
				break;
			case RULE_PMASK   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.proto;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &rule->m4.proto_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &rule->m6.proto_mask;	
				}
				ret = atoi(ptr);
				if(ret < 0 || ret > 255){
					return -1;
				}
				memcpy(addr, &ret, sizeof(char));

				break;
			default:
				break;

		}
	}
	return 0;
}



/*
*  0, successfully
*  -1, error
*  1, end;
*/

int rulereader_readnext(rulereader_t * self, grule_t * rule)
{
	char buf[65536];
	char buf2[65536];
	char * ptr;

	ssize_t nsize;
	int ret;
	
	nn_assert(self);
	nn_assert(rule);

	memset(rule, 0, sizeof(grule_t));
	
	do{

		if((!self->file) || feof(self->file)){
			if(self->file){
				fclose(self->file);
				self->file = NULL;
			}
			if(self->file_index >= self->file_no){
				return 1;
			}

			self->file = fopen(self->file_path[self->file_index], "r");
			self->file_index ++;
			self->line_no = 0;
			if(self->file == NULL){
				fprintf(stderr, "Can't open file %s, skip it\n", self->file_path[self->file_no - 1]);
				continue;
			}
			fprintf(stderr, "Open rule file %s.\n", self->file_path[self->file_no - 1]);
		}
		while((ptr =  fgets(buf, sizeof(buf), self->file)) != NULL){

			strcpy(buf2, buf);
			self->line_no++;
			nsize = strlen(ptr);
			if((size_t)nsize >= sizeof(buf) - 1){
				fprintf(stderr, "One line is more the %ld bytes.\n", sizeof(buf));
				fprintf(stderr, "skip bad rule \"%s\" @\"%s\":%ld\n", buf, self->file_path[self->file_no - 1], self->line_no);
				//fprintf(stderr, "Skiping %s, lineno: %ld\n", self->file_path[self->file_no - 1], self->line_no);
				//goto break;
				break;
			}	

			nsize = strstrim(buf);
			if(nsize == 0 || buf[0] == '#' || buf[0] == ';'){
				continue;
			}

			ret = parse_grule(buf, rule);

			if(ret != 0){
				fprintf(stderr, "skip bad rule \"%s\" @\"%s\":%ld\n", buf, self->file_path[self->file_no - 1], self->line_no);
				continue;
			}
			strstrim(buf2);
			//printf("Rule: %s----\n", buf2);
			return 0;
			goto __break;
		}
		
		__break:
		break;
	}while(1);
	return 1;
}

int rulereader_destroy(rulereader_t * self)
{

	unsigned int i;
	
	nn_assert(self);

	for( i = 0; i < self->file_no; i++){
		nn_free(self->file_path[i]);
	}
	if(self->file_path) nn_free(self->file_path);
	if(self->file) fclose(self->file);
	nn_free(self);
	return 0;
}


