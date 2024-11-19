#include "ulid_struct.hh"
#include <string.h>
#include <time.h>
#include <pthread.h>
using namespace std;

#ifdef __cplusplus
extern "C" {
#endif
void ulid_uuid_generate(unsigned char result[16]) 
{
    static __thread std::mt19937 generator(time(NULL) * pthread_self());
    ulid::ULID ulid;
    ulid::EncodeTimeNow(ulid);
	ulid::EncodeEntropyMt19937(generator, ulid);
    memcpy(result, ulid.data, 16);
}

#ifdef __cplusplus
}
#endif
