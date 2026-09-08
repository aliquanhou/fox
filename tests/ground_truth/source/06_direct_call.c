/* 06_direct_call.c — direct function calls */
__declspec(noinline) int gt_helper(int x) {
    return x * x;
}

__declspec(noinline) int gt_caller(int a, int b) {
    int x = gt_helper(a);
    int y = gt_helper(b);
    return x + y;
}

__declspec(noinline) int gt_chain(int n) {
    int r = gt_helper(n);
    r = gt_caller(r, n);
    return r;
}

int main(void) {
    return gt_chain(5);
}
