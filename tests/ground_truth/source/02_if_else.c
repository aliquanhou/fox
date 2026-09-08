/* 02_if_else.c — simple if/else branch */
__declspec(noinline) int gt_max(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

__declspec(noinline) int gt_classify(int x) {
    if (x > 0) {
        return 1;
    } else if (x < 0) {
        return -1;
    } else {
        return 0;
    }
}

int main(void) {
    return gt_max(5, 3) + gt_classify(-2);
}
