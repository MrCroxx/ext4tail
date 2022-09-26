#include <stdio.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define PMAX 4096

int
main(int argc, char *argv[])
{
    char buffer[PMAX];
    struct file *file = open("/ebs/risingwave/Cargo.toml");
    char *path = d_absolute_path(file, &buffer[0], PMAX);
    printf("%s", path);
    
	return 0;
}