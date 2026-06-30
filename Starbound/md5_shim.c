#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

static int (*r_init)(void *);
static int (*r_update)(void *, const void *, size_t);
static int (*r_final)(unsigned char *, void *);

__attribute__((constructor))
static void load_real(void)
{
    void *h = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_GLOBAL);
    if (!h) h = dlopen("libcrypto.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) return;
    r_init   = dlsym(h, "MD5_Init");
    r_update = dlsym(h, "MD5_Update");
    r_final  = dlsym(h, "MD5_Final");
}

int MD5_Init(void *c)                                  { return r_init(c); }
int MD5_Update(void *c, const void *d, size_t n)       { return r_update(c, d, n); }
int MD5_Final(unsigned char *md, void *c)              { return r_final(md, c); }
