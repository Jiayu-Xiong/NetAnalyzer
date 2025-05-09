#include <iostream>
using namespace std;
typedef struct list {
	list* prev;
	list* next;
}list;
#define list_for_each(pos, head) \
      for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_prev(pos, head) \
      for (pos = (head)->prev; pos != (head); pos = pos->prev)
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

class BasicList
{
public:
	void InitList(list& L)
	{
		L.next = &L;
		L.prev = &L;
	}
	void __list_add(struct list* insert,
		struct list* next,
		struct list* prev)
	{
		next->prev = insert;
		prev->next = insert;
		insert->prev = prev;
		insert->next = next;
	}

	void push_front(struct list* insert, struct list* head)
	{
		__list_add(insert, head->next, head);
	}

	void push_back(struct list* insert, struct list* head)
	{
		__list_add(insert, head, head->prev);
	}

	void list_add_before(struct  list* insert, struct list* node)
	{
		node->prev->next = insert;
		insert->prev = node->prev;
		insert->next = node;
		node->prev = insert;
	}

	void list_add_after(struct list* insert, struct list* node)
	{
		insert->next = node->next;
		insert->prev = node;
		node->next->prev = insert;
		node->next = insert;
	}

	void __list_del(struct list* next, struct list* prev)
	{
		next->prev = prev;
		prev->next = next;
	}

	void __list_del_node(struct list* node)
	{
		__list_del(node->next, node->prev);
	}

	void list_del(struct list* node)
	{
		__list_del_node(node);
		node->next = NULL;
		node->prev = NULL;
	}

	void list_replace(struct list* old, struct list* insert)
	{
		insert->next = old->next;
		insert->prev = old->prev;
		old->prev->next = insert;
		old->next->prev = insert;
	}

	int list_is_first(const struct list* node,
		const struct list* head)
	{
		return (node->prev == head);
	}

	int list_is_last(const struct list* node,
		const struct list* head)
	{
		return (node->next == head);
	}

	int list_empty(const struct list* head)
	{
		return (head->next == head);
	}
};