#include <stdint.h>
#include <stddef.h>
typedef struct gomem_yara_library gomem_yara_library;
typedef struct gomem_yara_rules gomem_yara_rules;
typedef struct {const char *namespace_name,*text;} gomem_yara_source;
typedef struct {const char *name,*json;} gomem_yara_global;
typedef struct {
 char *namespace_name,*rule,*pattern;
 uint64_t offset,length;
 int rule_only;
} gomem_yara_match;
typedef struct {
 gomem_yara_match *matches;
 size_t count,capacity;
 uint64_t bytes,budget;
 uint32_t limit;
 int error;
} gomem_yara_result;
gomem_yara_library *gomem_yara_load(const char *path);
gomem_yara_rules *gomem_yara_compile(gomem_yara_library *,const gomem_yara_source *,size_t,const gomem_yara_global *,size_t,char **,char **);
int gomem_yara_serialize(gomem_yara_rules *,void **,size_t *);
gomem_yara_rules *gomem_yara_deserialize(gomem_yara_library *,const void *,size_t);
void gomem_yara_rules_free(gomem_yara_rules *);
int gomem_yara_scan(gomem_yara_rules *,const void *,size_t,uint64_t,gomem_yara_result *);
void gomem_yara_result_free(gomem_yara_result *);
