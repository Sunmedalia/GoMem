/* Standalone CodeView corpus. No system SDK or acquired memory is used. */
typedef unsigned long long u64;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY;
enum state { gone=-1, idle=0, running=3, running_alias=3 };
struct flags { unsigned a:3; signed b:5; unsigned c:9; };
struct packed_flags { unsigned char a:3; signed char b:5; unsigned char c:1; };
struct _KPROCESS { u64 DirectoryTableBase; };
struct _EPROCESS {
    LIST_ENTRY ActiveProcessLinks;
    void *UniqueProcessId, *InheritedFromUniqueProcessId;
    char ImageFileName[16];
    u64 CreateTime;
    struct _KPROCESS Pcb;
    enum state state;
    struct flags flags;
    struct packed_flags packed;
    union { long signed_value; unsigned long mask; };
    unsigned short grid[2][3];
    int (*callback)(void);
};
int answer(void) { return 42; }
struct _EPROCESS SystemProcess;
LIST_ENTRY PsActiveProcessHead = { &SystemProcess.ActiveProcessLinks, &SystemProcess.ActiveProcessLinks };
struct _EPROCESS SystemProcess = {
    .ActiveProcessLinks = { &PsActiveProcessHead, &PsActiveProcessHead },
    .UniqueProcessId = (void*)4, .InheritedFromUniqueProcessId = (void*)0,
    .ImageFileName = "System", .CreateTime = 133800000000000000ULL,
    .Pcb = { 0x1000 }, .state = gone,
    .flags = {5,-7,257}, .packed = {6,-4,1}, .signed_value = -987,
    .grid = {{1,2,3},{4,5,6}}, .callback = answer
};
static volatile int private_value = -123;
void entry(void) { for (;;) { private_value++; } }
