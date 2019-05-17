#ifndef _DYNAMIC_ARRAY_H_
#define _DYNAMIC_ARRAY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define DYNAMIC_ARRAY_DEBUG		(1)

typedef void * dynamic_array_handle;

typedef int (* dynamic_array_iterate_cb)(int index, void *struct_data, void *user_arg);
typedef int (* dynamic_array_safe_copy_cb)(int index, void *new_data, void *old_data);

dynamic_array_handle dynamic_array_init(int struct_len, int array_init_num, int array_max_num);
void dynamic_array_destroy(dynamic_array_handle dah, dynamic_array_iterate_cb cb, void *);
int dynamic_array_append(dynamic_array_handle dah, void *struct_data, int struct_len);
int dynamic_array_append_distinct(dynamic_array_handle dah, void *struct_data, int struct_len);
void *dynamic_array_fetch(dynamic_array_handle dah, int index);
int dynamic_array_get_num(dynamic_array_handle dah);
void *dynamic_array_get_data(dynamic_array_handle dah);
void *dynamic_array_get_last_item(dynamic_array_handle dah);
int dynamic_array_iterate(dynamic_array_handle dah, dynamic_array_iterate_cb cb, void *user_arg);
dynamic_array_handle dynamic_array_quick_copy(dynamic_array_handle old_dah);

#ifdef __cplusplus
}
#endif

#endif

