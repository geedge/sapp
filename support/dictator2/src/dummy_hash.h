#ifndef _DUMMY_HTABLE_H_
#define _DUMMY_HTABLE_H_
#include <string.h>//using memset
#define	DUMMY_HASH_SIZE	2048
#define	DUMMY_COLLISION_SIZE	2048
struct dummy_pair_t
{
	long key;
	long value;
};
struct dummy_htable_t
{
	struct dummy_pair_t array[DUMMY_HASH_SIZE+DUMMY_COLLISION_SIZE];
	long collision_cnt;
};
inline void dummy_htable_init(struct dummy_htable_t* table)
{
	memset(table,0,sizeof(struct dummy_htable_t));
	return;
}
inline long dummy_htable_read(struct dummy_htable_t* table,long key,long *value)
{
	int i=0;
	int idx=key%DUMMY_HASH_SIZE;
	if(table->array[idx].key==key)
	{
		*value=table->array[idx].value;
		return 1;
	}
	else if(table->array[idx].key==0)
	{
		return 0;
	}
	else
	{
		for(i=DUMMY_HASH_SIZE;i<DUMMY_HASH_SIZE+table->collision_cnt;i++)
		{
			if(table->array[i].key==key)
			{
				*value=table->array[i].value;
				return 1;
			}
		}
		return 0;
	}
}
inline int dummy_htable_add(struct dummy_htable_t* table,long key,long value)
{
	int idx=key%DUMMY_HASH_SIZE;
	long previous_key=0,previous_value=0;
	assert(key!=0);
	previous_key=__sync_lock_test_and_set(&(table->array[idx].key),key);
	if(previous_key==0)
	{
		return 0;
	}
	previous_value=table->array[idx].value;
	table->array[idx].value=value;

	assert(table->collision_cnt<DUMMY_COLLISION_SIZE);
	idx=DUMMY_HASH_SIZE+__sync_fetch_and_add(&(table->collision_cnt),1);
	previous_key=__sync_fetch_and_add(&(table->array[idx].key),previous_key);
	table->array[idx].value=previous_value;
	assert(previous_key==0);
	return idx;
}
#endif
