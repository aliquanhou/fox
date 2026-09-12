/* FOX RM-8 round-trip target: small but exercises switch/loop/fn-ptr/struct. */
#include <stdio.h>

struct counters {
    int hits;
    int misses;
    int total;
};

static int classify(int v) {
    switch (v) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        default: return -1;
    }
}

static int sum_range(int n) {
    int s = 0;
    int i = 0;
    while (i < n) {
        s += i;
        i++;
    }
    return s;
}

int main(void) {
    struct counters c;
    c.hits = 0;
    c.misses = 0;
    c.total = 5;

    int k;
    for (k = 0; k < c.total; k++) {
        int r = classify(k);
        if (r > 0) c.hits += r;
        else c.misses++;
    }

    int (*fn)(int) = classify;
    int q = fn(c.hits);

    printf("hits=%d misses=%d sum=%d q=%d\n",
           c.hits, c.misses, sum_range(c.total), q);
    return 0;
}
