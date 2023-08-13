#include<linux/if_ether.h>
#include<bpf/in.h>
#include<bcc/proto.h>

int dns_matching(struct __sk_buff *skb){
    u8 *cursor = 0;

    //Checking the IP protocol::
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    
}
