#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/timer.h>
#include <net/netlink.h>
#include <net/sock.h>

static struct nf_hook_ops nfho;
static struct sock* nl_sk = NULL;
static unsigned char flag = 0;

unsigned int hook_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff*))
{
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	unsigned char host_hop[6] = {0x00,0x00,0x00,0x00,0x00,0x31};
	memcpy(dst_mac, skb_mac_header(skb), 6);
	memcpy(src_mac, skb_mac_header(skb)+6, 6);
	printk("rcv a pkt from %x:%x:%x:%x:%x:%x to %x:%x:%x:%x:%x:%x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
	if(flag == 0){
		return(NF_ACCEPT);
	}
	else{
		if(src_mac[5] == host_hop[5]){
			return(NF_QUEUE);
		}
		return(NF_ACCEPT);
	}
	return(NF_ACCEPT);
}



void nl_data_ready (struct sk_buff *__skb)
{
 	struct sk_buff *skb;
 	struct nlmsghdr *nlh;
 	u32 pid;
  	int rc;
  	int len = NLMSG_SPACE(1200);
  	char str[100];

  	printk("net_link: data is ready to read.\n");
  	skb = skb_get(__skb);

  	if (skb->len >= NLMSG_SPACE(0)) {
    	nlh = nlmsg_hdr(skb);
   		printk("net_link: recv %s.\n", (char *)NLMSG_DATA(nlh));
   		memcpy(str,NLMSG_DATA(nlh), sizeof(str)); 
		printk("str[0] is %d\n",str[0]);
    	pid = nlh->nlmsg_pid; 
    	printk("net_link: pid is %d\n", pid);
   		kfree_skb(skb);

    	skb = alloc_skb(len, GFP_ATOMIC);
    	if (!skb){
      	printk(KERN_ERR "net_link: allocate failed.\n");
      	return;
    }
    nlh = nlmsg_put(skb,0,0,0,1200,0);
    NETLINK_CB(skb).pid = 0;
	
	if(str[0] == 1){
		flag = 1;
		memcpy(NLMSG_DATA(nlh), "start", 6);
	}
	else if(str[0] == 2){
		flag = 0;
		memcpy(NLMSG_DATA(nlh), "end", 4);
	}
    printk("net_link: going to send.\n");
    rc = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
    if (rc < 0) {
      printk(KERN_ERR "net_link: can not unicast skb (%d)\n", rc);
    }
    printk("net_link: send is ok.\n");
  }
  return;
}

		
int channel_init(void)
{

	printk("channel_init\n");
	
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho);
	
	nl_sk = netlink_kernel_create(&init_net, 21, 0, nl_data_ready, NULL, NULL);
	if(!nl_sk){
		printk("netlink_kernel_create error\n");
		return(-1);
	}
	printk("netlink_kernel_create ok \n");
	return 0;
}

void channel_exit(void)
{
	printk("channel_exit\n");


	nf_unregister_hook(&nfho);

	if(nl_sk != NULL){
		sock_release(nl_sk->sk_socket);
	}
	printk("netlink remove ok \n");
	
}

module_init(channel_init);
module_exit(channel_exit);

