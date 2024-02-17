#ifndef __LIST_H__
#define __LIST_H__

/**
 * 使用该宏，需要链表有如下结构�?
 *
 * struct entry {
 * 		data_type data;
 * 		struct entry *prev;
 * 		struct entry *next;
 * };
 *
 * struct list {
 * 		int count;
 * 		struct entry *entries;
 * };
*/
#define LIST_ADD(list, entry) do { 					\
	entry->prev = NULL;								\
	entry->next = list->entries;					\
	if (list->entries) list->entries->prev = entry;	\
	list->entries = entry; \
} while (0)

#define LIST_DEL(list, entry) do {						\
	if (entry->prev) 									\
		entry->prev->next = entry->next;				\
	else												\
		list->entries = entry->next;					\
	if (entry->next) entry->next->prev = entry->prev;	\
	entry->prev = entry->next = NULL;					\
} while (0)

#endif
