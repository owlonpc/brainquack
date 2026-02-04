#ifndef DA_H_
#define DA_H_

#if !defined(DA_REALLOC) || !defined(DA_ALLOC) || !defined(DA_FREE)
#include <stdlib.h>
#endif /* DA_REALLOC */

#ifndef DA_REALLOC
#define DA_REALLOC realloc
#endif // DA_REALLOC

#ifndef DA_ALLOC
#define DA_ALLOC malloc
#endif // DA_ALLOC

#ifndef DA_FREE
#define DA_FREE free
#endif // DA_FREE

#ifndef DA_ASSERT
#include <assert.h>
#define DA_ASSERT assert
#endif // DA_ASSERT

#ifndef DA_INIT_CAP
#define DA_INIT_CAP 256
#endif

#define da_append(da, item)                  \
	do {                                     \
		da_reserve((da), (da)->count + 1);   \
		(da)->items[(da)->count++] = (item); \
	} while (0)

#define da_free(da) DA_FREE((da)->items)

// mixin necessary fields easily
#define da_fields(typ_) \
	typ_  *items;       \
	size_t count, capacity

// append many items from pointer and size
#define da_append_many(da, new_items, new_items_count)                                            \
	do {                                                                                          \
		da_reserve((da), (da)->count + (new_items_count));                                        \
		memcpy((da)->items + (da)->count, (new_items), (new_items_count) * sizeof(*(da)->items)); \
		(da)->count += (new_items_count);                                                         \
	} while (0)

// this macro allows indexing from the end using negative numbers
#define da_at(da, pos)                                                                                        \
	((DA_ASSERT((int64_t)(pos) < (int64_t)(da)->count && -(int64_t)(pos) <= (int64_t)(da)->count), (pos) < 0) \
	         ? ((da)->items + (da)->count + (pos))                                                            \
	         : ((da)->items + (pos)))

#define da_pop(da) (da)->items[(DA_ASSERT((da)->count > 0), --(da)->count)]

#define da_last(da) (da)->items[(DA_ASSERT((da)->count > 0), (da)->count - 1)]

#define da_remove_unordered(da, i)                     \
	do {                                               \
		DA_ASSERT((i) < (da)->count);                  \
		(da)->items[(i)] = (da)->items[--(da)->count]; \
	} while (0)

// Foreach over Dynamic Arrays. Example:
// ```c
// typedef struct {
//     da_fields(int);
// } Numbers;
//
// Numbers xs = {0};
//
// da_append(&xs, 69);
// da_append(&xs, 420);
// da_append(&xs, 1337);
//
// da_foreach(int, x, &xs) {
//     // `x` here is a pointer to the current element. You can get its index by taking a difference
//     // between `x` and the start of the array which is `x.items`.
//     size_t index = x - xs.items;
//     printf("xs[%zu] = %d\n", index, *x);
// }
// ```
#define da_foreach(Type, it, da) for (Type *it = (da)->items; it < (da)->items + (da)->count; ++it)

#define da_reserve(da, expected_capacity) __da_reserve((StubArray *)(da), expected_capacity, sizeof(*(da)->items))

typedef struct StubArray {
	void  *items;
	size_t count;
	size_t capacity;
} StubArray;

void __da_reserve(StubArray *da, size_t expected_capacity, size_t item_size);

typedef struct {
	char  *items;
	size_t count;
	size_t capacity;
} StringBuilder;

#endif // DA_H_

#ifdef DA_IMPLEMENTATION

#define TT_EVAL(tt)
#define TT_STR(tt) "tt"

void
__da_reserve(StubArray *da, size_t expected_capacity, size_t item_size)
{
	if (da->capacity > expected_capacity)
		return;
	if (da->capacity == 0)
		da->capacity = DA_INIT_CAP;
	while (da->capacity < expected_capacity)
		da->capacity *= 2;
	da->items = DA_REALLOC(da->items, da->capacity * item_size);
}

#endif // DA_IMPLEMENTATION
