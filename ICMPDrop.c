#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


#define  DEVICE_NAME "ICMPDrop"
#define  CLASS_NAME  "ICMP"
#define NIPQUAD(addr) ((unsigned char *)&addr)[0], ((unsigned char *)&addr)[1], ((unsigned char *)&addr)[2], ((unsigned char *)&addr)[3]
#define MAKEPORT(port) ((unsigned char *)&port)[0] * 256 + ((unsigned char *)&port)[1]

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bahar Boroomand");
MODULE_DESCRIPTION("A Linux driver for Packet Dropping.");
MODULE_VERSION("1.0");


char list[100][100];
int listIterator = 0;
int mode = 0; //white list or black list ?? --> 0 == black and 1 == white

static int    majorNumber;
static int    numberOpens = 0;
static struct class *  ModuleClass  = NULL;
static struct device * ModuleDevice = NULL;

static int     devel_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *); 

char buffer[48];
struct sk_buff * sock_buff;
struct iphdr * ip_header;
struct udphdr * udp;

unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff *));

static struct file_operations fops =
{
	.open = devel_open,
	.write = dev_write,
	.release = dev_release,
};

static struct nf_hook_ops drop __read_mostly = {
	.pf = NFPROTO_IPV4,
	.priority= NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_IN,
	.hook = (nf_hookfn *) icmp_hook
};

static int __init ICMPDrop_init(void) {
	printk(KERN_INFO "Packet DROP :: Initializing the Device Driver\n");

	/* Let's create and register the Device driver and it's minor and major :D */
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0){
		printk(KERN_ALERT "Packet DROP :: Device failed to register a major number\n");
		return majorNumber;
	}
	printk(KERN_INFO "Packet DROP :: Device registered correctly with major number %d\n", majorNumber);
	ModuleClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(ModuleClass)){
		unregister_chrdev(majorNumber, DEVICE_NAME);
	   	printk(KERN_ALERT "Packet DROP :: Failed to register device class\n");
	    return PTR_ERR(ModuleClass);
	}
	printk(KERN_INFO "Packet DROP :: device class registered correctly\n");
	ModuleDevice = device_create(ModuleClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(ModuleDevice)){
	    class_destroy(ModuleClass);
	    unregister_chrdev(majorNumber, DEVICE_NAME);
	    printk(KERN_ALERT "Packet DROP :: Failed to create the device\n");
	    return PTR_ERR(ModuleDevice);
	}
	printk(KERN_INFO "Packet DROP :: device class created correctly\n");
	printk(KERN_INFO "drop initialization\n");
	nf_register_net_hook(&init_net,&drop);
	return 0;
}


static void __exit ICMPDrop_exit(void) {
	device_destroy(ModuleClass, MKDEV(majorNumber, 0));
	class_unregister(ModuleClass);
	class_destroy(ModuleClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	printk(KERN_INFO "Packet DROP :: Goodbye :D!\n");
	printk(KERN_INFO "drop exiting!\n");
	nf_register_net_hook(&init_net, &drop);

}


unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff *)) {
	sock_buff = skb;
	/* check the transport and network header */
	ip_header = (struct iphdr *) skb_network_header(sock_buff);
	udp = (struct udphdr *) skb_transport_header(sock_buff);

	int port = MAKEPORT(udp->source);
	
	char des[100];
	sprintf(des, "%d.%d.%d.%d:%d",NIPQUAD(ip_header->saddr), port);
	printk(KERN_INFO "Packet DROP :: a packet recieved from %s\n",des);
	printk(KERN_INFO "Packet DROP :: we are in %s mode\n", mode == 0 ? "black list" : "white list");
	
	// search in the list
	int i = 0;	
	int status = 0; // if status == 1 then drop it :D
	if(mode == 1){
		status = 1;
	}
	for(; i < listIterator; i++){
		if(mode == 0){
			if(!strcmp(des, list[i])){
				status = 1;
				printk(KERN_INFO "Black list : packet from forbbiden IP! dropping packet: %s\n", list[i]);
				break;
			}
		}else{
			if(!strcmp(des, list[i])){
				status = 0;
				printk(KERN_INFO "white list :packet accepted!\n: %s\n", list[i]);
				break;
			}	
		}		
	}
	if(status == 0){
		printk(KERN_INFO "packet accepted!\n");
		return NF_ACCEPT;
	}else{
		printk(KERN_INFO "packet dropped!\n");
		return NF_DROP;	
	}
}


static int devel_open(struct inode *inodep, struct file *filep){
	numberOpens++;
	printk(KERN_INFO "Packet DROP :: Device has been opened %d time(s)\n", numberOpens);
	return 0;
}


static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	sprintf(list[listIterator], "%s", buffer);   
	printk(KERN_INFO "Received from the user : %s\n", list[listIterator]);
	if(!strcmp(list[listIterator], "white")){
		mode = 1;
		listIterator = 0;
	}else if(!strcmp(list[listIterator], "black")){
		mode = 0;
		listIterator = 0;	
	}else{
		listIterator++;
	}	
	return sizeof(list[listIterator]);
}


static int dev_release(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "Packet DROP :: Device successfully closed\n");
	return 0;
}


module_init(ICMPDrop_init);
module_exit(ICMPDrop_exit);






