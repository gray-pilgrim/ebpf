#!/usr/bin/python
from bcc import BPF
from time import sleep

program = """
BPF_HASH(clones); //isn't this a global variable
//and hence not allowed??

int hello_world(void *ctx){
u64 uid;
u64 counter = 0;
u64 *p;

p = clones.lookup(&uid);
if(p != NULL)
{
    counter = *p;
}
counter++;
clones.update(&uid,&counter);
//uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

//bpf_trace_printk("id: %d\\n",uid);//only bottom 4 bytes store uid
//bpf_trace_printk("Hello world!\\n"); //not good for production applications
//the above reads and writes from a single pipe
return 0;
}
"""

b = BPF(text=program)
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")
b.trace_print();
#triggered every time a new process is triggered on the system

while True:
    sleep(2)
    s = ""
    if len(b["clones"].items()):
        for k,v in b["clones"].items():
            s+= "ID {}: {}\t".format(k.value, v.value)
        print(s)
    else:
        print("No entries yet")