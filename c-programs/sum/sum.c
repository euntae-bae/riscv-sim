int sumArr(int *arr, int len) {
    int sum = 0;
    int i;
    for (i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

int main(void) {
    int arr1[5] = { 10, 20, 30, 40, 50 };
    int result = sumArr(arr1, 5);
    return 0;
}