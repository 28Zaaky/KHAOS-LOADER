#pragma once
#include <stddef.h>

void evs_dec(char *out, const unsigned char *enc, size_t n);

#define EVS_D(out, arr) evs_dec((out), (arr), sizeof(arr))
