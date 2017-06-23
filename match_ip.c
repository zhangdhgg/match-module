#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");
static struct nf_hook_ops nfhook_ops;

/* 127.0.0.1 */
static char *drop_ipaddr = "127.0.0.1";
/* Usage: *(unsigned int *)drop_ipaddr */
/* static char *drop_ipaddr = "\x7f\x00\x00\01"; */

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb_tmp = skb;
	struct iphdr *iph;

	iph = ip_hdr(skb_tmp);
	printk("%u %u\n", iph->saddr, in_aton(drop_ipaddr));
	if (iph->saddr == in_aton(drop_ipaddr)) {
		printk("Match packet \n");
		return NF_DROP;
	} else {
		printk("Do not match packet \n");
		return NF_ACCEPT;
	}
}

int init_module()
{
	nfhook_ops.hook = hook_func;
	nfhook_ops.hooknum = NF_INET_PRE_ROUTING;
	nfhook_ops.pf = PF_INET;
	nfhook_ops.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfhook_ops);
	pr_info("Filter match-ip install into kernel");
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&nfhook_ops);
	pr_info("Filter match-ip removed from kernel");
}
