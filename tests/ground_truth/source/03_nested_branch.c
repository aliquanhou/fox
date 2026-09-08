/* 03_nested_branch.c — nested if/else */
__declspec(noinline) int gt_nested(int a, int b, int c) {
    if (a > 0) {
        if (b > 0) {
            return c + 1;
        } else {
            return c + 2;
        }
    } else {
        if (c > 0) {
            return a + b;
        }
        return 0;
    }
}

__declspec(noinline) int gt_grade(int score) {
    if (score >= 90) return 4;
    if (score >= 80) return 3;
    if (score >= 70) return 2;
    if (score >= 60) return 1;
    return 0;
}

int main(void) {
    return gt_nested(1, 2, 3) + gt_grade(85);
}
