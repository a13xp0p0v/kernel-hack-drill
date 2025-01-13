#ifndef _DRILL_H
#define _DRILL_H

/*
 * A buffer size for storing string "act arg1 arg2", where
 *  - act is 1 symbol,
 *  - arg1 is maximum 18 symbols (0xffffffffffffffff),
 *  - arg2 is maximum 18 symbols (0xffffffffffffffff),
 *  - two spaces and null byte at the end.
 */
#define DRILL_ACT_SIZE 40

enum drill_act_t {
	DRILL_ACT_NONE = 0,
	DRILL_ACT_ALLOC = 1,
	DRILL_ACT_CALLBACK = 2,
	DRILL_ACT_SAVE_VAL = 3,
	DRILL_ACT_FREE = 4,
	DRILL_ACT_RESET = 5
};

#define DRILL_ITEM_SIZE 3300

struct drill_item_t {
	unsigned long foo;
	unsigned long bar;
	void (*callback)(void);
	unsigned long data[]; /* C99 flexible array */
};

#endif	/* _DRILL_H */
