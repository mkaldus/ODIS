#include <stdio.h>

int main() {
    	FILE *rules;
    
 	rules = fopen("ruls", "r");
	if (!rules) {
		perror("opening config file\n");
	    	exit (1);
	}
	printf("parsing rules\n");
    	parse_rules(stdin);
    	fclose(rules);
        return 0;
}
