/* 04_loop.c — simple for/while loops */
__declspec(noinline) int gt_sum_n(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

__declspec(noinline) int gt_count_down(int start) {
    int count = 0;
    while (start > 0) {
        count++;
        start--;
    }
    return count;
}

int main(void) {
    return gt_sum_n(100) + gt_count_down(50);
}
