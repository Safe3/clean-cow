#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <asm/uaccess.h>
#include <asm/siginfo.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kallsyms.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/binfmts.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif

#define MADV_NORMAL     0 
#define MADV_DONTNEED   4 
    
unsigned long *sys_call_table;


static void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size )
{
	char *p;

	for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++ )
		if ( memcmp(p, needle, needle_size) == 0 )
			return (void *)p;

	return NULL;
}

unsigned long *find_sys_call_table ( void )
{
	char **p;
	unsigned long sct_off = 0;
	unsigned char code[512];

	rdmsrl(MSR_LSTAR, sct_off);
	memcpy(code, (void *)sct_off, sizeof(code));

	p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

	if ( p )
	{
		unsigned long *sct = *(unsigned long **)((char *)p + 3);

		// Stupid compiler doesn't want to do bitwise math on pointers
		sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

		return sct;
	}
	else
		return NULL;
}

inline unsigned long disable_wp ( void )
{
	unsigned long cr0;
	preempt_disable();
	barrier();
	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);
	return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
	write_cr0(cr0);
	barrier();
	preempt_enable();
}

typedef asmlinkage long (*madvise_ptr)(unsigned long start, size_t len, int behavior);

madvise_ptr old_sys_madvise;

asmlinkage long new_sys_madvise(unsigned long start, size_t len, int behavior)
{
	if(behavior == MADV_DONTNEED) behavior = MADV_NORMAL;
	return old_sys_madvise(start,len,behavior);
}

static int __init safe3_init(void)
{
	unsigned long o_cr0;
	
	sys_call_table = find_sys_call_table();
	if (sys_call_table==NULL)
	{
		printk("cannot find sys_call_table addr\n");
		return -1;
	}

	o_cr0 = disable_wp();
	old_sys_madvise=(madvise_ptr)sys_call_table[__NR_madvise];
	sys_call_table[__NR_madvise]=(unsigned long)new_sys_madvise;
	restore_wp(o_cr0);

	return 0;
}

static void __exit safe3_exit(void)
{
	unsigned long o_cr0;

	o_cr0 = disable_wp();
	sys_call_table[__NR_madvise]=(unsigned long)old_sys_madvise;
	restore_wp(o_cr0);
}

module_init(safe3_init);
module_exit(safe3_exit);

MODULE_AUTHOR("Safe3 http://www.uusec.com/");
MODULE_DESCRIPTION("Linux Clean COW Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1.0");
