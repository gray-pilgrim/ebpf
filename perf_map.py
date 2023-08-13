#!/usr/bin/python
from bcc import BPF

program = """
BPF_PERF_OUTPUT(output);
struct data_t {
int pid;
int uid;
char message[12];
char command[18];
};

int hello(void *ctx)
{
    struct data_t data = {};
    char message[12] = "Hello world";
     
    data.pid = bpf_get_current_pid_tgid()>>32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(&data.message, sizeof(data.message),message);
    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)
clone= b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello")

def print_event(cpu, data, size):
    data= b["output"].event(data)
    print(f"{data.pid}{data.uid} {data.command.decode()} {data.message.decode()}")

b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()


# data is now passed through a ring buffer map instead of single trace pipe