/* Synthetic, standalone DWARF corpus. It contains no acquired memory. */
typedef unsigned long long u64;
enum state { gone = -1, idle = 0, running = 3, running_alias = 3 };
struct task_struct;
typedef struct task_struct task_t;
int answer(void);
struct flags { unsigned a:3; signed b:5; unsigned c:9; };
struct __attribute__((packed)) packed_flags { unsigned a:3; signed b:5; unsigned c:1; };
struct task_struct {
    struct task_struct *next;
    task_t *alias;
    int (*callback)(void);
    int pid;
    enum state state;
    struct flags flags;
    const volatile unsigned short grid[2][3];
    union { long signed_value; unsigned long mask; };
    struct packed_flags packed;
    unsigned char bytes[3];
    char comm[16];
};
struct task_struct init_task = {
    .next = &init_task, .alias = &init_task, .callback = answer, .pid = -123, .state = gone,
    .flags = { .a = 5, .b = -7, .c = 257 },
    .grid = {{1,2,3},{4,5,6}}, .signed_value = -987,
    .packed = { .a = 6, .b = -4, .c = 1 },
    .bytes = {0x12,0x34,0x56}, .comm = "swapper/0"
};
const char linux_banner[] = "Linux version 6.1.0-gomem-dwarf (synthetic corpus) #1 SMP\n";
const char version[] = "Darwin Kernel Version 16.7.0: synthetic gomem corpus\n";
void _start(void) { for (;;) { } }
int answer(void) { return 42; }
