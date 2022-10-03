#ifndef VEC_H
#define VEC_H

#include <stddef.h>

struct cape_string_vec {
    char **data;
    size_t len;
    size_t cap;
};

int cape_string_vec_push(struct cape_string_vec *vec, const char *string);

void cape_string_vec_free(struct cape_string_vec *vec);

#endif /* VEC_H */
