/* 05_nested_loop.c — nested loops */
__declspec(noinline) int gt_matrix_sum(int rows, int cols, int matrix[10][10]) {
    int total = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            total += matrix[i][j];
        }
    }
    return total;
}

__declspec(noinline) int gt_triangular(int n) {
    int count = 0;
    for (int i = 0; i < n; i++) {
        for (int j = i; j < n; j++) {
            count += i + j;
        }
    }
    return count;
}

int main(void) {
    int m[10][10] = {0};
    return gt_matrix_sum(3, 3, m) + gt_triangular(5);
}
