#ifndef __RULEREAD_H
#define __RULEREAD_H
#include <stdlib.h>

#include "grule.h"

__BEGIN_DECLS


struct __rulereader;
typedef struct __rulereader rulereader_t;


//rulereader_t * rulereader_init();

rulereader_t * rulereader_init( char **file, size_t file_no);


//int rulereader_hasmore(rulereader_t * self);

int rulereader_readnext(rulereader_t * self, grule_t * rule);

int rulereader_destroy(rulereader_t * self);

__END_DECLS
	
#endif 

