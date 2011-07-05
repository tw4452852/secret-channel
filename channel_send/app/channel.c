#include <libipq.h> 
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netfilter.h> 
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>

#define BUFSIZE 2048 
#define MAX_PAYLOAD 1024

struct tw_pkt{
	char buf[BUFSIZE];
	struct tw_pkt* next;
	struct tw_pkt* pre;
};



struct tw_queue_head{
	int count;
	struct tw_pkt* head;
	struct tw_pkt* end;
};


static int result_in[800], result_out[1400];
static struct sockaddr_nl src_addr, dest_addr;
static struct nlmsghdr *nlh = NULL;
static struct iovec iov;
static int sock_fd;
static struct msghdr msg;
static int begin = 0, begin_ok = 0, end = 0, end_ok = 0;
static int pos = 0, str_len = 0;
static struct timeval pre, now;
static struct tw_queue_head my_pkt_head;
static struct ipq_handle *h; 
static int enough = 0;

void code(int a[],int n,int out[])
{
  int i,j,k,l,q[7],aa[4];
  int b[4][7]={{1,0,0,0,1,1,1},{0,1,0,0,1,1,0},{0,0,1,0,1,0,1},{0,0,0,1,0,1,1}};//定义生成矩阵
  for(i=0;i<(n/4);i++)
  {
	  aa[0]=a[4*i];aa[1]=a[4*i+1];aa[2]=a[4*i+2];aa[3]=a[4*i+3];
      for (j=0;j<7;j++)
	 { q[j]=0;
		for(k=0;k<4;k++)
		q[j]+=aa[k]*b[k][j];/////与生成矩阵相乘
	 }
		 for(k=0;k<7;k++)
		{
	     
		 out[7*i+k]=q[k]%2;////将生成的放入out[]中
		}
  }
  for(i=0;i<(7*n/4);i++){
	  if(i % 14 == 0){
		  printf(" ");
	  }
  	  printf("%d",out[i]);
  }
}

void transform(int* begin, int num)
{
	int i = 7;

	do{
		*(begin + i) = num % 2;
		num = num / 2;
		i--;
	}while(num > 0);
}


int encode(char str[], int len)
{
	int i, j;

	memset(result_in, 0, sizeof(result_in));
	memset(result_out, 0, sizeof(result_out));
	printf("ASCII:");
	for(i = 0; i < len; i++){
		if(str[i] == 0){
			break;
		}
		else{
			printf("%d->",str[i]);
			transform(result_in + 8 * i, str[i]);
			for(j = 0; j < 8; j++){
				printf("%d", result_in[8 * i + j]);
			}
			printf(" ");
		}
	}
	printf("\n");
	printf("hanming:");
	code(result_in, 8 * i, result_out);
	printf("\n");
	str_len = i;
	begin = 1;
	return(0);
}

void connect_to_kernel(char* input)
{
	sock_fd = socket(PF_NETLINK, SOCK_RAW, 21);

	memset(&msg, 0, sizeof(msg));
	

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */
	src_addr.nl_groups = 0; /* not in mcast groups */

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */

	nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid(); /* self pid */
	nlh->nlmsg_flags = 0;
	/* Fill in the netlink message payload */
	strcpy(NLMSG_DATA(nlh), input);

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf(" Sending message to kernel ...\n");
	sendmsg(sock_fd, &msg, 0);

	/* Read message from kernel */
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	printf(" Waiting message from kernel ...\n");
	recvmsg(sock_fd, &msg, 0);
	printf(" Received message from kernel is: %s\n",NLMSG_DATA(nlh));
	close(sock_fd);
}



long interval_time(ipq_packet_msg_t* m)
{
	long result;
	if(pre.tv_sec == 0 && pre.tv_usec == 0){
		pre.tv_sec = m->timestamp_sec;
		pre.tv_usec = m->timestamp_usec;
		return(0);
	}
	else{
		now.tv_sec = m->timestamp_sec;
		now.tv_usec = m->timestamp_usec;
		result = (now.tv_sec - pre.tv_sec) * 1000000 + (now.tv_usec - pre.tv_usec);
		pre.tv_sec = now.tv_sec;
		pre.tv_usec = now.tv_usec;
		return(result);
	}
}



void enqueue (struct tw_pkt* tmp)
{
	ipq_packet_msg_t *m = ipq_get_packet(tmp->buf);

	my_pkt_head.count++;
	printf("%ld packet_id enqueue\n",m->packet_id);
//	if(my_pkt_head.head != NULL){
//		printf("before head:%ld,end:%ld\n",ipq_get_packet(my_pkt_head.head->buf)->packet_id, ipq_get_packet(my_pkt_head.end->buf)->packet_id);
//	}
	if(my_pkt_head.head == NULL){
		my_pkt_head.head = tmp;
		my_pkt_head.end = tmp;
	}
	else{
		my_pkt_head.end->next = tmp;
		tmp->pre = my_pkt_head.end;
		my_pkt_head.end = tmp;
	}
//	printf("after head:%ld,end:%ld \n",ipq_get_packet(my_pkt_head.head->buf)->packet_id, ipq_get_packet(my_pkt_head.end->buf)->packet_id);
}

void dequeue()
{
	my_pkt_head.count--;
	struct tw_pkt* tmp;

	if(my_pkt_head.head == NULL){
		return;
	}
	else{
		tmp = my_pkt_head.head->next;
		free(my_pkt_head.head);
		my_pkt_head.head = tmp;
		return;
	}
}


void packet_send()
{
	ipq_set_verdict(h, ipq_get_packet(my_pkt_head.head->buf)->packet_id, NF_ACCEPT, 0, NULL);
	printf("%ld packet_id send\n", ipq_get_packet(my_pkt_head.head->buf)->packet_id);
	dequeue();
}


void* tw_send(void* arg)
{
	int finish = 0, end = 0;
	int i = 0;

	while(1){
		if(end == 0){
			if(my_pkt_head.count >= 2){
				if(finish == 1){
					packet_send();
					i++;
					usleep(700000);
					packet_send();
					i++;
					end = 1;
				}
				else if(i == 0){
					packet_send();
					i++;
					usleep(500000);
					packet_send();
					i++;
				}	
				else{
					if(result_out[pos] == 0){
						pos++;
						packet_send();
						i++;
						usleep(100000);
						packet_send();
						i++;
						if(i == (2 * (1 + (str_len * 14)))){
							finish = 1;
						}
					}
					else{
						pos++;
						packet_send();
						i++;
						usleep(300000);
						packet_send();
						i++;
						if(i == (2 * (1 + (str_len * 14)))){
							finish = 1;
						}
					}
				}
			}
			else{
				continue;
			}
		}
		else if(end == 1 && my_pkt_head.count > 0){
			packet_send();
			i++;
		}
		else{
			continue;
		}
	}
}



void die() 
{ 
	ipq_perror("passer"); 
	ipq_destroy_handle(h); 
	exit(1); 
} 


int main(int argc, char **argv) 
{ 
	int status; 
	char str[100];
	char input[2];
	long interval = 0;
	int  i = 0;
	struct tw_pkt* tmp = NULL;
	pthread_t p;

	h = ipq_create_handle(0, PF_INET); 
	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if(status < 0){
		die();
	}
	memset(str, 0, 100);
	memset(input, 0, 2);
	pre.tv_sec = now.tv_sec = 0;
	pre.tv_usec = now.tv_usec = 0;
	my_pkt_head.count = 0;
	my_pkt_head.head = my_pkt_head.end = NULL;

	printf("input a string\n");
	fgets(str, 100, stdin);
//	memcpy(str, argv[1], 100);
	encode(str, 100);
	
	input[0] = 1;
	
   	connect_to_kernel(input);

	printf("start to send information...\n");

	do{ 
		struct tw_pkt* tmp = malloc(sizeof(struct tw_pkt));
		memset(tmp->buf, 0, BUFSIZE);
		tmp->pre = tmp->next = NULL;
		status = ipq_read(h, tmp->buf, BUFSIZE, 0); 
		if(status < 0){
			die();
		}
		switch (ipq_message_type(tmp->buf)) { 
			case NLMSG_ERROR:{ 
				fprintf(stderr, "Received error message %d ", 
						ipq_get_msgerr(tmp->buf)); 
				break; 
			}
			case IPQM_PACKET:{ 
				ipq_packet_msg_t *m = ipq_get_packet(tmp->buf);
				printf("%ld packet_id rcv \n", m->packet_id);		
				enqueue(tmp);
				i++;
				if(i == 2){
					pthread_create(&p, NULL, tw_send, NULL);
				}
				break; 
			} 
			default:{
				fprintf(stderr, "Unknown message type! "); 
				break;
			}
		}
	} while (1); 

	input[0] = 2;
	connect_to_kernel(input);
	
	ipq_destroy_handle(h); 
	return 0; 
} 

