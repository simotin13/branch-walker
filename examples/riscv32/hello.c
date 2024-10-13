#include <stdio.h>
int add(int a, int b) {
    return a + b;
}

int main() {
    int sum = 0;
    sum = add(1, 2);
    if (sum == 10)
    {
        printf("sum is 10\n");
    } else {
        printf("sum is not 10\n");
    }
    return 0;
}
