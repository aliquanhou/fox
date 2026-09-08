/* 09_function_pointer.c — indirect calls via function pointers */
typedef int (*binary_op)(int, int);

__declspec(noinline) int gt_add(int a, int b) { return a + b; }
__declspec(noinline) int gt_sub(int a, int b) { return a - b; }
__declspec(noinline) int gt_mul(int a, int b) { return a * b; }

__declspec(noinline) int gt_apply(binary_op op, int x, int y) {
    return op(x, y);
}

__declspec(noinline) int gt_dispatch(int selector, int a, int b) {
    binary_op ops[3] = {gt_add, gt_sub, gt_mul};
    if (selector >= 0 && selector < 3) {
        return gt_apply(ops[selector], a, b);
    }
    return -1;
}

int main(void) {
    return gt_dispatch(0, 10, 20) + gt_dispatch(2, 3, 4);
}
