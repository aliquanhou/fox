/* 08_switch.c — switch statement (jump table candidate) */
__declspec(noinline) int gt_switch_day(int day) {
    switch (day) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        case 4: return 40;
        case 5: return 50;
        case 6: return 60;
        case 7: return 70;
        default: return 0;
    }
}

__declspec(noinline) int gt_switch_op(int op, int a, int b) {
    switch (op) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return (b != 0) ? a / b : 0;
        default: return -1;
    }
}

int main(void) {
    return gt_switch_day(3) + gt_switch_op(0, 10, 20);
}
