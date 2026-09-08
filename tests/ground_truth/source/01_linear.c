/* 01_linear.c — linear code, no branches */
__declspec(noinline) int gt_add(int a, int b) {
    int sum = a + b;
    int result = sum * 2;
    return result;
}

__declspec(noinline) int gt_linear_main(int x) {
    int a = x + 1;
    int b = a * 3;
    int c = b - 5;
    return c;
}

int main(void) {
    return gt_add(3, 4) + gt_linear_main(10);
}
