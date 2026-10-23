//go:build cgo && (windows || linux || darwin)

#include "bridge.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
static void *load_library(const char *path){
 int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0);if(!n)return NULL;
 wchar_t *wide=calloc((size_t)n,sizeof(wchar_t));if(!wide)return NULL;
 if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,n)){free(wide);return NULL;}
 HMODULE result=LoadLibraryExW(wide,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);free(wide);return result;
}
#define SYMBOL(h,n) GetProcAddress((HMODULE)h,n)
#define UNLOAD(h) FreeLibrary((HMODULE)h)
#else
#include <dlfcn.h>
static void *load_library(const char *path){return dlopen(path,RTLD_NOW|RTLD_LOCAL);}
#define SYMBOL(h,n) dlsym(h,n)
#define UNLOAD(h) dlclose(h)
#endif

// Opaque handles and signatures from the fixed 1.9.0 public C API. Only the
// two-size_t match and buffer values cross the ABI; rules/patterns stay opaque.
typedef struct {size_t offset,length;} native_match;
typedef struct {const uint8_t *data;size_t length;} native_buffer;
struct gomem_yara_library{
 void *handle;
 int (*compiler_create)(uint32_t,void **);
 int (*add_source)(void *,const char *);
 int (*errors_json)(void *,native_buffer **);
 int (*warnings_json)(void *,native_buffer **);
 void (*buffer_destroy)(native_buffer *);
 void *(*build)(void *);
 void (*compiler_destroy)(void *);
 void (*rules_destroy)(void *);
 int (*scanner_create)(const void *,void **);
 void (*scanner_destroy)(void *);
 int (*timeout)(void *,uint64_t);
 int (*on_rule)(void *,void (*)(const void *,void *),void *);
 int (*scan)(void *,const uint8_t *,size_t);
 int (*rule_name)(const void *,const uint8_t **,size_t *);
 int (*rule_namespace)(const void *,const uint8_t **,size_t *);
 int (*pattern_name)(const void *,const uint8_t **,size_t *);
 int (*patterns)(const void *,void (*)(const void *,void *),void *);
 int (*matches)(const void *,void (*)(const native_match *,void *),void *);
};
struct gomem_yara_rules{gomem_yara_library *library;void *rules;};
gomem_yara_library *gomem_yara_load(const char *path){
 gomem_yara_library *lib=calloc(1,sizeof(*lib));if(!lib)return NULL;
 lib->handle=load_library(path);if(!lib->handle){free(lib);return NULL;}
#define BIND(field,name) lib->field=(void *)SYMBOL(lib->handle,name);if(!lib->field)goto failure;
 BIND(compiler_create,"yrx_compiler_create");BIND(add_source,"yrx_compiler_add_source");BIND(errors_json,"yrx_compiler_errors_json");BIND(buffer_destroy,"yrx_buffer_destroy");
 BIND(warnings_json,"yrx_compiler_warnings_json");
 BIND(build,"yrx_compiler_build");BIND(compiler_destroy,"yrx_compiler_destroy");BIND(rules_destroy,"yrx_rules_destroy");
 BIND(scanner_create,"yrx_scanner_create");BIND(scanner_destroy,"yrx_scanner_destroy");BIND(timeout,"yrx_scanner_set_timeout");BIND(on_rule,"yrx_scanner_on_matching_rule");BIND(scan,"yrx_scanner_scan");
 BIND(rule_name,"yrx_rule_identifier");BIND(rule_namespace,"yrx_rule_namespace");BIND(pattern_name,"yrx_pattern_identifier");BIND(patterns,"yrx_rule_iter_patterns");BIND(matches,"yrx_pattern_iter_matches");
#undef BIND
 // Never unload an initialized YARA-X runtime: its Wasmtime signal handlers
 // are process-global. Only missing-symbol loads can be unloaded safely.
 return lib;
failure:UNLOAD(lib->handle);free(lib);return NULL;
}
gomem_yara_rules *gomem_yara_compile(gomem_yara_library *lib,const char *source,char **diagnostics,char **warnings){
 void *compiler=NULL;if(lib->compiler_create(32,&compiler)!=0)return NULL; // disable includes
 if(lib->add_source(compiler,source)!=0){
  native_buffer *buffer=NULL;
  if(lib->errors_json(compiler,&buffer)==0&&buffer){
   if(buffer->length<=65536){*diagnostics=calloc(buffer->length+1,1);if(*diagnostics)memcpy(*diagnostics,buffer->data,buffer->length);}
   lib->buffer_destroy(buffer);
  }
  lib->compiler_destroy(compiler);return NULL;
 }
 native_buffer *warning=NULL;
 if(lib->warnings_json(compiler,&warning)!=0||!warning){lib->compiler_destroy(compiler);return NULL;}
 if(warning->length>65536){lib->buffer_destroy(warning);lib->compiler_destroy(compiler);return NULL;}
 *warnings=calloc(warning->length+1,1);
 if(!*warnings){lib->buffer_destroy(warning);lib->compiler_destroy(compiler);return NULL;}
 memcpy(*warnings,warning->data,warning->length);lib->buffer_destroy(warning);
 void *compiled=lib->build(compiler);lib->compiler_destroy(compiler);if(!compiled)return NULL;
 gomem_yara_rules *rules=calloc(1,sizeof(*rules));if(!rules){lib->rules_destroy(compiled);return NULL;}
 rules->library=lib;rules->rules=compiled;return rules;
}
void gomem_yara_rules_free(gomem_yara_rules *r){if(r){r->library->rules_destroy(r->rules);free(r);}}
typedef struct{
 gomem_yara_library *lib;gomem_yara_result *result;
 const uint8_t *namespace_name,*rule,*pattern;size_t ns_len,rule_len,pattern_len;
 size_t rule_start;
} collect_context;
static char *copy_name(const uint8_t *p,size_t n){char *s=calloc(n+1,1);if(s&&n)memcpy(s,p,n);return s;}
static void append_match(collect_context *c,const native_match *m,int rule_only){
 gomem_yara_result *r=c->result;if(r->error)return;
 uint64_t bytes=c->ns_len+c->rule_len+c->pattern_len+(rule_only?0:m->length);
 if(r->count>=r->limit||bytes>r->budget-r->bytes){r->error=1;return;}
 if(r->count==r->capacity){size_t capacity=r->capacity?r->capacity*2:16;if(capacity>r->limit)capacity=r->limit;
  void *p=realloc(r->matches,capacity*sizeof(*r->matches));if(!p){r->error=2;return;}r->matches=p;r->capacity=capacity;
 }
 gomem_yara_match *out=&r->matches[r->count];memset(out,0,sizeof(*out));
 out->namespace_name=copy_name(c->namespace_name,c->ns_len);out->rule=copy_name(c->rule,c->rule_len);out->pattern=copy_name(c->pattern,c->pattern_len);
 if(!out->namespace_name||!out->rule||!out->pattern){free(out->namespace_name);free(out->rule);free(out->pattern);r->error=2;return;}
 out->rule_only=rule_only;if(!rule_only){out->offset=m->offset;out->length=m->length;}r->count++;r->bytes+=bytes;
}
static void on_match(const native_match *m,void *user){append_match(user,m,0);}
static void on_pattern(const void *pattern,void *user){
 collect_context *c=user;if(c->result->error)return;
 if(c->lib->pattern_name(pattern,&c->pattern,&c->pattern_len)!=0||c->pattern_len>4096){c->result->error=2;return;}
 if(c->lib->matches(pattern,on_match,c)!=0)c->result->error=2;
}
static void on_rule(const void *rule,void *user){
 collect_context *c=user;if(c->result->error)return;
 if(c->lib->rule_name(rule,&c->rule,&c->rule_len)!=0||c->lib->rule_namespace(rule,&c->namespace_name,&c->ns_len)!=0||c->rule_len>4096||c->ns_len>4096){c->result->error=2;return;}
 c->rule_start=c->result->count;
 if(c->lib->patterns(rule,on_pattern,c)!=0){c->result->error=2;return;}
 if(c->result->count==c->rule_start&&!c->result->error){c->pattern=NULL;c->pattern_len=0;append_match(c,NULL,1);}
}
int gomem_yara_scan(gomem_yara_rules *r,const void *data,size_t length,uint64_t seconds,gomem_yara_result *result){
 void *scanner=NULL;gomem_yara_library *lib=r->library;int code=lib->scanner_create(r->rules,&scanner);if(code)return code;
 collect_context c={.lib=lib,.result=result};
 code=lib->timeout(scanner,seconds);
 if(!code)code=lib->on_rule(scanner,on_rule,&c);
 if(!code)code=lib->scan(scanner,data,length);
 lib->scanner_destroy(scanner);return code;
}
void gomem_yara_result_free(gomem_yara_result *r){
 for(size_t n=0;n<r->count;n++){free(r->matches[n].namespace_name);free(r->matches[n].rule);free(r->matches[n].pattern);}
 free(r->matches);r->matches=NULL;r->count=0;
}
