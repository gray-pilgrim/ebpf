#include<linux/bpf.h>
#include "bpf/bpf_helpers.h"

int counter =0;
SEC("xdp")//no semicolons
int helloworld(void *ctx){  //always same
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//check bpftool prog load hello.bpf.o /sys/fs/bpf/hello with --legacy