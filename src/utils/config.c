#include <stdio.h>

extern int measure;
extern char results_filename[256];

int load_config() {
    FILE *fp = fopen("./config-cracker", "r");

    if (fp) {
        char buf1[256];

        fscanf(fp, "%s %d", buf1, &measure);
        fscanf(fp, "%s %s", buf1, results_filename);

        fclose(fp);
    } else {
        return -1;
    }

    return 0;
}