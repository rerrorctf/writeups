#include <stdio.h>
#include <string.h>
#include <stdlib.h>

float rand_float() {
  return (float)rand() / RAND_MAX;
}

void print_money() {
	system("/bin/sh");
}

void gamble() {
	float f[4];
	float target = rand_float();
	printf("Enter your lucky numbers: ");
	scanf(" %lf %lf %lf %lf %lf %lf %lf", f,f+1,f+2,f+3,f+4,f+5,f+6);
	if (f[0] == target || f[1] == target || f[2] == target || f[3] == target || f[4] == target || f[5] == target || f[6] == target) { 
		printf("You win!\n");
		// due to economic concerns, we're no longer allowed to give out prizes.
		// print_money();
	} else {
		printf("Aww dang it!\n");
	}
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

	char buf[20];
	srand(420);
	while (1) {
		gamble();
		getc(stdin); // consume newline
		printf("Try again? ");
		fgets(buf, 20, stdin);
		if (strcmp(buf, "no.\n") == 0) {
			break;
		}
	}
}


