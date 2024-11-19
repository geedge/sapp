#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <uuid/uuid.h>
    
void ulid_uuid_generate(uuid_t uuid_res);

#ifdef __cplusplus
}
#endif
