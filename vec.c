#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "banned.h"
#include "vec.h"

int cape_string_vec_push(struct cape_string_vec *vec, const char *string) {
    char *str = NULL;

    if (string) {
        str = strdup(string);
        if (!str) {
            perror("malloc");
            goto fail;
        }
    }

    if (vec->cap == 0) {
        char **new_data = malloc(sizeof(char *));
        if (!new_data) {
            perror("malloc");
            goto fail;
        }
        vec->cap = 1;
        vec->data = new_data;
    } else if (vec->len >= vec->cap) {
        size_t new_cap = vec->cap * 2;
        char **new_data = NULL;
        new_data = realloc(vec->data, new_cap * sizeof(char *));
        if (!new_data) {
            perror("realloc");
            goto fail;
        }
        vec->data = new_data;
        vec->cap = new_cap;
    }

    vec->data[vec->len] = str;
    vec->len++;
    return 0;

fail:
    free(str);
    return -1;
}

void cape_string_vec_free(struct cape_string_vec *vec) {
    if (vec) {
        for (size_t i = 0; i < vec->len; i++) {
            free(vec->data[i]);
        }
        free(vec->data);
        vec->data = NULL;
        vec->cap = 0;
        vec->len = 0;
    }
}
