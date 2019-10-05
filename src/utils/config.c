#include <stdio.h>
#include <stdlib.h>

#include "cracker-errors.h"
#include "print.h"

extern int measure;
extern char *results_filename;

int load_config() {
    FILE *fp = fopen("./config-cracker", "r");

    if (fp) {
        char buf1[256];

        fscanf(fp, "%s %d", buf1, &measure);
        results_filename = getenv("RESULTS_FILENAME");

        // If measuring performance, the file to write to
        // must be opened properly.
        if (measure && !results_filename) {
            fclose(fp);
            return ERR_RESULTS_FNAME;
        }

        fclose(fp);
    } else {
        return ERR_OPEN_CONFIG;
    }

    return 0;
}