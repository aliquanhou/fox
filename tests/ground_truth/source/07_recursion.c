/* 07_recursion.c — recursive functions */
__declspec(noinline) int gt_factorial(int n) {
    if (n <= 1) return 1;
    return n * gt_factorial(n - 1);
}

__declspec(noinline) int gt_fibonacci(int n) {
    if (n <= 1) return n;
    return gt_fibonacci(n - 1) + gt_fibonacci(n - 2);
}

__declspec(noinline) int gt_gcd(int a, int b) {
    if (b == 0) return a;
    return gt_gcd(b, a % b);
}

int main(void) {
    return gt_factorial(5) + gt_fibonacci(7) + gt_gcd(48, 18);
}
