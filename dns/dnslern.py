#! /usr/bin/python3

from bcc import BPF


program=r"""
int first (void *ctx){
    bpf_trace_printk("Hello world! execve() is calling\n");
    return 0;
}

"""

bpf = BPF(text=program)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="first")
while True:
    try:
        (_,_,_,_,_, event_b)=bpf.trace_fields()
        events=event_b.decode('utf8')
        if 'Hello World' in events:
            print(events)
    except ValueError:
        continue
    except KeyboardInterrupt:
        break