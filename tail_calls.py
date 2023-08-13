#!/usr/bin/python
from bcc import BPF
import ctypes as ct

program="""
BPF_PROG_ARRAY(syscall, 300);
int hello(struct bpf_raw_tracepoint_args *ctx){
int opcode= ctx->args[1];
syscall.call(ctx, opcode);
bpf_trace_printk("Another syscall:%d", opcode);
}

int hello_execve(void *ctx){
bpf_trace_printk("Executing a program");
return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx){
if(ctx->args[1] == 222){
bpf_trace_printk("Create a timer");
}
else if (ctx->args[1] == 226){
bpf_trace_printk("Delete a timer");
}
else {
bpf_trace_printk("Some other timer options");
}
return 0;
}

int ignore_opcode(void *ctx){
return 0;
}
"""

b=BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve",BPF.RAW_TRACEPOINT)
timer_fn= b.load_func("hello_timer",BPF.RAW_TRACEPOINT)

prog_array=b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)


# Ignore some syscalls that come up a lot
prog_array[ct.c_int(0)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(44)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(11)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(271)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(13)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(14)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(7)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(46)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(3)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(1)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(47)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(270)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(6)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(232)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(202)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(16)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(5)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(5)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(29)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(56)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(57)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(63)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(64)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(66)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(72)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(73)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(79)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(98)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(101)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(115)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(131)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(134)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(135)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(139)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(172)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(233)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(280)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(291)] = ct.c_int(ignore_fn.fd)
b.trace_print()