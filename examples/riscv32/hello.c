#include <stdio.h>
int is_even(int num) {
    int even = 1;
    if (num % 2) {
    	even = 0;
    }
    return even;
}

int main() {
    int ret;
    int num = 3;
    ret = is_even(num);
    if (ret)
    {
        printf("num:[%d] is even\n");
    } else {
        printf("num:[%d] is odd\n");
    }
    return 0;
}
