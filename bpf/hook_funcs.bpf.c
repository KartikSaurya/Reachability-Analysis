#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 0);
} events SEC(".maps");

// **Match this section suffix to the Go symbol name exactly.**
SEC("uprobe/vulnerableHandler")
int trace_vuln(struct pt_regs *ctx) {
    struct { char func[64]; } ev = {};
    __builtin_memcpy(ev.func, "vulnerableHandler", 17);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
