/* 10_optimized.c — designed for -O2 optimization testing */
__declspec(noinline) int gt_opt_sum(int* arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

__declspec(noinline) int gt_opt_fold(int x) {
    int a = x * 2 + 1;
    int b = a * 3 - 2;
    int c = b / 2;
    return c + x;
}

__declspec(noinline) int gt_opt_branch(int flag, int a, int b) {
    if (flag) {
        return a * b + a;
    }
    return b - a;
}

int main(void) {
    int arr[5] = {1, 2, 3, 4, 5};
    return gt_opt_sum(arr, 5) + gt_opt_fold(10) + gt_opt_branch(1, 3, 4);
}
