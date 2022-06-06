#include <stdio.h>

int add(int n1, int n2) {
    return n1 + n2;
}

int main(void) {
    int num1 = 100;
    int num2 = 5000;
    int num3 = add(num1, num2);
    return 0;
}