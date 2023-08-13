from bcc import BPF
from bcc.utils import printb

program="""
int hello(void *ctx){
bpf_trace_printk("Hella wold");
return 0;
}
"""

bpfer = BPF(text=program)
bpfer.attach_kprobe(event=bpfer.get_syscall_fnname("clone"),fn_name="hello")

print("%-18s %-12s %-8s %-12s" % ("TIME(s)","PID","COMM","MESSAGE"))

while True:
    try:
        (task,pid,cpu,flags,ts,msg)=bpfer.trace_fields()
    except ValueError:
        break
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
