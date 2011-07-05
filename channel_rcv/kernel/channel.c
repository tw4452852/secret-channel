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
static int recv_buf[800],recv[1400];
static int pos = 0;
static long pre = 0;
static int begin_ok = 0, end_ok = 0;
static int flag = 0;

unsigned int hook_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff*))
{
	long interval;
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	unsigned char pre_hop[6] = {0x00,0x00,0x00,0x00,0x00,0x12};
	
	memcpy(dst_mac, skb_mac_header(skb), 6);
	memcpy(src_mac, skb_mac_header(skb) + 6, 6);
//	printk("recv a pkt from %x:%x:%x:%x:%x:%x to %x:%x:%x:%x:%x:%x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);

	if(src_mac[5] == pre_hop[5]){
		if(pre == 0){
			pre = jiffies;
		}
		else{
			interval = jiffies - pre;
			pre = jiffies;
			printk("interval = %ldms\n", interval);
			if((interval > 490) && (interval < 520)){
				if(begin_ok == 1){
					pos = 0;
					end_ok = 0;
					flag = 0;
					memset(recv, 0, sizeof(recv));
					printk("start again\n");
				}
				else{
					begin_ok = 1;
					flag = 0;
					printk("start\n");
				}
				return(NF_ACCEPT);
			}
			else if((interval > 690) && (interval < 720)){
				end_ok = 1;
				printk("finish\n");
				return(NF_ACCEPT);
			}
			else if((begin_ok == 1) && (end_ok == 0)){
				if(flag == 1){
					if((interval > 290) && (interval < 350)){
						recv[pos++] = 1;
						printk("1\n");
						flag = 0;
						return(NF_ACCEPT);
					}
					else if((interval > 90) && (interval < 150)){
						recv[pos++] = 0;
						printk("0\n");
						flag = 0;
						return(NF_ACCEPT);
					}
				}
				else if(flag == 0){
					flag = 1;
				}
			}
		}
	}
	return(NF_ACCEPT);
}

void transform(char str[], int i)
{
	int sum = 0;
	
	sum += (recv_buf[8 * i + 0] * 128);
	sum += (recv_buf[8 * i + 1] * 64);
 	sum += (recv_buf[8 * i + 2] * 32);
	sum += (recv_buf[8 * i + 3] * 16);
	sum += (recv_buf[8 * i + 4] * 8);
	sum += (recv_buf[8 * i + 5] * 4);
	sum += (recv_buf[8 * i + 6] * 2);
	sum += (recv_buf[8 * i + 7] * 1);
	
	printk("%d ",sum);
	str[i] = sum;
}

void pre_decode(int c[],int m,int workout[])
{   int d[7][3]={{1,1,1},{1,1,0},{1,0,1},{0,1,1},{1,0,0},{0,1,0},{0,0,1}};
    int i,k,l,z;
	int p[10],t[10],cc[7];
    for(i=0;i<(m/7);i++)
  {
	  cc[0]=c[7*i];cc[1]=c[7*i+1];cc[2]=c[7*i+2];cc[3]=c[7*i+3];cc[4]=c[7*i+4];	cc[5]=c[7*i+5];cc[6]=c[7*i+6];
      for (l=0;l<3;l++)
	  { p[l]=0;
		for(k=0;k<7;k++)
	    p[l]+=cc[k]*d[k][l];
	  }
      for(k=0;k<3;k++)
	  {
		 t[k]=p[k]%2;
	  }
    
   if(t[0]||t[1]||t[2])
   {z=4*t[0]+2*t[1]+t[2];
   cc[6-z]=1-cc[6-z];}
   
   for(k=0;k<4;k++)
   {workout[4*i+k]=cc[k];}
	}
//   for(i=0;i<(4*m/7);i++)
//	 printf("%d",workout[i]);
}

int decode(char str[], int len)
{
	int count, i;

	memset(str, 0, len);
	memset(recv_buf, 0, sizeof(recv_buf));
	pre_decode(recv, pos, recv_buf);
	count = pos / 14;
	for(i = 0; i < count; i++){
		transform(str, i);
	}
	printk("decode is %s\n", str);
	return(0);
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
	decode(str,sizeof(str));
	memcpy(NLMSG_DATA(nlh), str, sizeof(str));
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

