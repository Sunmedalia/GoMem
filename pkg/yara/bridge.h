#include <stdint.h>
#include <stddef.h>
typedef struct gomem_yara_library gomem_yara_library;
typedef struct gomem_yara_rules gomem_yara_rules;
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
gomem_yara_rules *gomem_yara_compile(gomem_yara_library *,const char *,char **,char **);
void gomem_yara_rules_free(gomem_yara_rules *);
int gomem_yara_scan(gomem_yara_rules *,const void *,size_t,uint64_t,gomem_yara_result *);
void gomem_yara_result_free(gomem_yara_result *);
