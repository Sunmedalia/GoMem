//go:build cgo && (linux || darwin || windows)

// The Capstone v5 public instruction ABI is deliberately isolated here.
// Reject other major versions before allocating or reading an instruction.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define CS_LOAD(path) LoadLibraryExA(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
#define CS_SYMBOL(h,name) GetProcAddress((HMODULE)h,name)
#define CS_UNLOAD(h) FreeLibrary((HMODULE)h)
#else
#include <dlfcn.h>
#define CS_LOAD(path) dlopen(path,RTLD_NOW|RTLD_LOCAL)
#define CS_SYMBOL(h,name) dlsym(h,name)
#define CS_UNLOAD(h) dlclose(h)
#endif

typedef struct {uint32_t id;uint64_t address;uint16_t size;uint8_t bytes[24];char mnemonic[32];char operands[160];void *detail;} gomem_cs_insn;
typedef struct {uint64_t address;uint16_t size;uint8_t bytes[24];char mnemonic[32];char operands[160];} gomem_instruction;
typedef struct gomem_cs {
 void *library;size_t handle;unsigned minor;int arch,flags;
 gomem_cs_insn *insn;
 unsigned (*version)(int *,int *);
 int (*open)(int,int,size_t *);
 int (*close)(size_t *);
 int (*option)(size_t,int,size_t);
 gomem_cs_insn *(*allocate)(size_t);
 void (*free_insn)(gomem_cs_insn *,size_t);
 uint8_t (*next)(size_t,const uint8_t **,size_t *,uint64_t *,gomem_cs_insn *);
} gomem_cs;
int gomem_cs_reset(gomem_cs *cs){
 if(cs->insn){cs->free_insn(cs->insn,1);cs->insn=NULL;}
 if(cs->handle){cs->close(&cs->handle);cs->handle=0;}
 size_t handle=0;if(cs->open(cs->arch,cs->flags,&handle)!=0)return 0;cs->handle=handle;
 if(cs->option(cs->handle,2,0)!=0||cs->option(cs->handle,5,0)!=0||(cs->arch==3&&cs->option(cs->handle,1,1)!=0))return 0;
 cs->insn=cs->allocate(cs->handle);return cs->insn!=NULL;
}
void gomem_cs_close(gomem_cs *cs){
 if(!cs)return;
 if(cs->insn)cs->free_insn(cs->insn,1);
 if(cs->handle)cs->close(&cs->handle);
 if(cs->library)CS_UNLOAD(cs->library);
 free(cs);
}
gomem_cs *gomem_cs_open(const char *path,int mode){
 gomem_cs *cs=calloc(1,sizeof(*cs));if(!cs)return NULL;
 cs->library=CS_LOAD(path);if(!cs->library){free(cs);return NULL;}
 cs->version=(void *)CS_SYMBOL(cs->library,"cs_version");cs->open=(void *)CS_SYMBOL(cs->library,"cs_open");
 cs->close=(void *)CS_SYMBOL(cs->library,"cs_close");cs->option=(void *)CS_SYMBOL(cs->library,"cs_option");
 cs->allocate=(void *)CS_SYMBOL(cs->library,"cs_malloc");cs->free_insn=(void *)CS_SYMBOL(cs->library,"cs_free");cs->next=(void *)CS_SYMBOL(cs->library,"cs_disasm_iter");
 if(!cs->version||!cs->open||!cs->close||!cs->option||!cs->allocate||!cs->free_insn||!cs->next){gomem_cs_close(cs);return NULL;}
 int major=0,minor=0;cs->version(&major,&minor);if(major!=5){gomem_cs_close(cs);return NULL;}cs->minor=minor;
 int arch,flags;switch(mode){case 0:arch=3;flags=4;break;case 1:arch=3;flags=8;break;case 2:arch=0;flags=0;break;case 3:arch=1;flags=0;break;case 4:arch=0;flags=16;break;default:gomem_cs_close(cs);return NULL;}
 cs->arch=arch;cs->flags=flags;
 // CS_OPT_DETAIL=2, CS_OPT_SKIPDATA=5: explicitly disable both. No invented
 // instructions or native detail allocations survive a decode call.
 if(!gomem_cs_reset(cs)){gomem_cs_close(cs);return NULL;}return cs;
}
unsigned gomem_cs_minor(gomem_cs *cs){return cs->minor;}
int gomem_cs_next(gomem_cs *cs,const void *data,size_t size,uint64_t address,gomem_instruction *out){
 const uint8_t *cursor=data;size_t remaining=size;uint64_t next_address=address;
 if(!cs->next(cs->handle,&cursor,&remaining,&next_address,cs->insn))return 0;
 uint16_t consumed=cs->insn->size;
 if(!consumed||consumed>24||consumed>size||cursor!=(const uint8_t *)data+consumed||remaining!=size-consumed||cs->insn->address!=address||next_address!=address+consumed||!memchr(cs->insn->mnemonic,0,32)||!memchr(cs->insn->operands,0,160))return 0;
 out->address=cs->insn->address;out->size=consumed;memcpy(out->bytes,cs->insn->bytes,consumed);memcpy(out->mnemonic,cs->insn->mnemonic,32);memcpy(out->operands,cs->insn->operands,160);return 1;
}
