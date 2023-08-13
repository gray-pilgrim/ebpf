from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

REQ_WRITE = 1

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request*);

void trace_start (struct pt_regs *ctx, struct request *req){
    u64 ts = bpf_ktime_get_ns();
    start.update(&req,&ts);

}

BPF_HISTOGRAM(hist);
void trace_complete (struct pt_regs *ctx, struct request *req){
    
    u64 delta, *ts;
    ts = start.lookup(&req);
    if(ts != 0){
        delta = bpf_ktime_get_ns()-*ts;
        hist.increment(bpf_log2l(delta/1000));
        start.delete(&req);
    }
}
""")

if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done",fn_name="trace_complete")
else :
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_complete")

try:
    sleep(99999999)
except KeyboardInterrupt:
    print()


b["hist"].print_log2_hist("latency")

