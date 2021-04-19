    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "42") == 0) {
        fprintf(stderr, "It depends!\n");
        exit(42);
    }
    printf("What is the meaning of life?\n");
    exit(0);
    }
