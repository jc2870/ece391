#include "list.h"

struct entry {
    int a,b,c;
    struct list list;
};

bool test_list()
{
    struct list head;
    struct entry e0;
    struct entry e1;
    struct entry e2;
    struct list *cur;
    struct entry *e;
    int i = 1;

    INIT_LIST(&head);
    e0.a = 1;
    e0.b = 2;
    e0.c = 3;
    e1.a = 4;
    e1.b = 5;
    e1.c = 6;
    e2.a = 7;
    e2.b = 8;
    e2.c = 9;
    list_add_tail(&head, &e0.list);
    list_add_tail(&head, &e1.list);
    list_add_tail(&head, &e2.list);

    list_for_each(cur, &head) {
        e = entry_list(cur, struct entry, list);
        if (e->a != i) {
            printf("value is %d, should be %d\n", e->a, i);
            return false;
        }
        i++;
        if (e->b != i) {
            printf("value is %d, should be %d\n", e->b, i);
            return false;
        }
        i++;
        if (e->c != i) {
            printf("value is %d, should be %d\n", e->c, i);
            return false;
        }
        i++;
    }

    return true;
}
