//go:build cgo && (linux || darwin || windows)

// Minimal read-only LeechCore v2 ABI adapter. No write, option setter, callback
// or general-purpose command is exposed to Go. The external library is optional.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define LC_LOAD(path) LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
#define LC_SYMBOL(h,name) GetProcAddress((HMODULE)h,name)
#define LC_UNLOAD(h) FreeLibrary((HMODULE)h)
#else
#include <dlfcn.h>
#define LC_LOAD(path) dlopen(path, RTLD_NOW | RTLD_LOCAL)
#define LC_SYMBOL(h,name) dlsym(h,name)
#define LC_UNLOAD(h) dlclose(h)
#endif

typedef struct {
 uint32_t version, verbosity;
 char device[260], remote[260];
 void *printf_callback;
 uint64_t max_address;
 uint32_t is_volatile, writable, is_remote, no_compress;
 char device_name[260];
} gomem_lc_config;
typedef struct gomem_lc {
 void *library, *handle;
 void *(*create)(gomem_lc_config *);
 void (*close)(void *);
 void (*memfree)(void *);
 uint32_t (*read)(void *, uint64_t, uint32_t, void *);
 uint32_t (*command)(void *, uint64_t, uint32_t, void *, void **, uint32_t *);
} gomem_lc;

void gomem_lc_close(gomem_lc *lc) {
 if (!lc) return;
 if (lc->handle) lc->close(lc->handle);
 if (lc->library) LC_UNLOAD(lc->library);
 free(lc);
}
gomem_lc *gomem_lc_open(const char *library,const char *device,const char *remote) {
 gomem_lc *lc=calloc(1,sizeof(*lc));
 if (!lc) return NULL;
 lc->library=LC_LOAD(library);
 if (!lc->library) {free(lc);return NULL;}
 lc->create=(void *)LC_SYMBOL(lc->library,"LcCreate");
 lc->close=(void *)LC_SYMBOL(lc->library,"LcClose");
 lc->memfree=(void *)LC_SYMBOL(lc->library,"LcMemFree");
 lc->read=(void *)LC_SYMBOL(lc->library,"LcRead");
 lc->command=(void *)LC_SYMBOL(lc->library,"LcCommand");
 if (!lc->create || !lc->close || !lc->memfree || !lc->read || !lc->command) {gomem_lc_close(lc);return NULL;}
 gomem_lc_config config={0};config.version=0xc0fd0002;
 if (strlen(device)>=260 || strlen(remote)>=260) {gomem_lc_close(lc);return NULL;}
 memcpy(config.device,device,strlen(device));memcpy(config.remote,remote,strlen(remote));
 lc->handle=lc->create(&config);
 if (!lc->handle) {gomem_lc_close(lc);return NULL;}
 return lc;
}
int gomem_lc_map(gomem_lc *lc,uint64_t **result,uint32_t *count) {
 void *data=NULL;uint32_t size=0;
 uint32_t ok=lc->command(lc->handle,UINT64_C(0x4000040000000000),0,NULL,&data,&size);
 if (!ok || !data || !size || size%24 || size/24>65536) {if(data)lc->memfree(data);return 0;}
 *result=malloc(size);
 if (!*result) {lc->memfree(data);return 0;}
 memcpy(*result,data,size);lc->memfree(data);*count=size/24;return 1;
}
int gomem_lc_read(gomem_lc *lc,uint64_t at,uint32_t size,void *data) {
 return lc->read(lc->handle,at,size,data)!=0;
}
