#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32);
BPF_HISTOGRAM(dist);

int do_entry(struct pt_regs *ctx)
{
    u32 pid;
    u64 tx;

    pid = bpf_get_current_pid_tgid();
    tx = bpf_ktime_get_ns();
    start.update(&pid, &tx);
    return 0;
}

int do_return(struct pt_regs *ctx)
{
    u32 pid;
    u64 *tsp, delta;
    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if(tsp != 0)
    {
        delta = bpf_ktime_get_ns() - *tsp;
        dist.increment(bpf_log2l(delta/1000));
        start.delete(&pid);
    }
}
