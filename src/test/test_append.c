#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "fcntl.h"
#include "logging.h"
#include "nffileV3/nffileV3.h"
#include "util.h"

int main(int argc, char *argv[]) {
    InitLog(0, "stderr", 0, 1);
    if (!CheckPath(argv[1], S_IFREG)) exit(EXIT_FAILURE);
    if (!CheckPath(argv[2], S_IFREG)) exit(EXIT_FAILURE);
    int rc = RenameAppendV3(argv[1], argv[2]);
    printf("RenameAppendV3 returned %d\n", rc);
    return rc;
}
