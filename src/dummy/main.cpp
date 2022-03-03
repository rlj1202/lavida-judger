#include <cstdio>
#include <unistd.h>

using namespace std;

// Memory Exceed
// unsigned char buffer[1024 * 1024 * 512];

int main() {
    int test;
    scanf("%d", &test);
    printf("%d\n", test * 2);

    // Bad System Call
    // int pid = fork();

    // Time Exceed
    // while (true) {}

    return 0;
}
