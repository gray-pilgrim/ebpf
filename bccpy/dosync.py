from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

#load BPF program
b=BPF(text="""
#include <uapi/linux/ptrace.h>
struct datum {
u32 pid;
u64 delta;
u64 timest;
};

BPF_PERF_OUTPUT(output);
BPF_HASH(last);
int do_trace(struct pt_regs *ctx){
struct datum data = {};
    u64 ts, *tsp, delta, key=0;
    //attempt to read stored timestamp
    tsp = last.lookup(&key);
    if(tsp != NULL){
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000){
        // output if time is less than one second
        data.pid = bpf_get_current_pid_tgid();
        data.delta = delta;
        data.timest = bpf_ktime_get_ns();
        output.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
    }

    //update stored timestamp
    ts=bpf_ktime_get_ns();
    last.update(&key,&ts);
    return 0;
}""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"),fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

#process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["output"].event(data)
    if start == 0:
        start = int(event.timest)
    print("At time %.2f s:multiple syncs detected, last %s ms ago" % ((int(event.timest) - start) / 1000000000, event.delta/1000000))
    
#loop with callback to print_event
b["output"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()