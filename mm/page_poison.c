// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/page_ext.h>
#include <linux/poison.h>
#include <linux/ratelimit.h>
#include <linux/kasan.h>
#include <linux/xarray.h>
#include <linux/slab.h>

static bool want_page_poisoning __read_mostly;

DEFINE_XARRAY(page_usage_table);
static atomic_t page_usage_initialized = ATOMIC_INIT(0);
static spinlock_t page_usage_lock;

static void init_page_usage(void)
{
	spin_lock_init(&page_usage_lock);

	atomic_inc(&page_usage_initialized);
	printk("monish [%s:%d] DMA page usage started\n", __func__, __LINE__);
}

static int __init early_page_poison_param(char *buf)
{
	if (!buf)
		return -EINVAL;
	init_page_usage();
	return strtobool(buf, &want_page_poisoning);
}
early_param("page_poison", early_page_poison_param);

/**
 * page_poisoning_enabled - check if page poisoning is enabled
 *
 * Return true if page poisoning is enabled, or false if not.
 */
struct page_usage {
	u32 count;
	unsigned long last_inc;
	unsigned long last_dec;
	u32	num_inc;
	u32	num_dec;
	int free_while_used;
	int pid;
	char comm[TASK_COMM_LEN + 1];
};

static void pu_print(unsigned long pfn, const char *msg, struct page_usage *pu)
{
	printk("PU [%lu] %s\n", pfn, msg);
	if (!pu)
		return;
	printk("PU [%lu] count: %d pid: %d comm: %s\n", pfn, pu->count, pu->pid, pu->comm);
	printk("PU [%lu] num_inc: %u num_dec: %u\n", pfn, pu->num_inc, pu->num_dec);
}

void inc_page_usage(unsigned long pfn)
{
	struct page_usage *pu;
	unsigned long flags;

	if (!atomic_read(&page_usage_initialized))
		return;

	spin_lock_irqsave(&page_usage_lock, flags);
	pu = xa_load(&page_usage_table, pfn);
	if (pu) {
		if (!pu->count)
			pu->free_while_used = 0;
		pu->count += 1;
	} else {
		pu = kzalloc(sizeof(*pu), GFP_ATOMIC);
		if (pu) {
			pu->count = 1;
			pu->pid = current->pid;
			strncpy(pu->comm, current->comm, TASK_COMM_LEN);
			pu->comm[TASK_COMM_LEN] = 0;
			if (xa_store(&page_usage_table, pfn, pu, GFP_ATOMIC))
				pu_print(pfn, "fail to insert", NULL);
		} else {
			pu_print(pfn, "fail to alloc", NULL);
		}
	}
	if (pu) {
		pu->last_inc = jiffies;
		pu->num_inc += 1;
	}
	spin_unlock_irqrestore(&page_usage_lock, flags);
}
EXPORT_SYMBOL(inc_page_usage);

void dec_page_usage( unsigned long pfn)
{
	struct page_usage *pu;
	unsigned long flags;

	if (!atomic_read(&page_usage_initialized))
		return;

	spin_lock_irqsave(&page_usage_lock, flags);
	pu = xa_load(&page_usage_table, pfn);
	if (pu) {
		if (pu->count)
			pu->count -= 1;
		else
			pu_print(pfn, "release when not in use", pu);
		pu->num_dec += 1;
		pu->last_dec = jiffies;

		if (pu->free_while_used) {
			pu_print(pfn, "late release", pu);
			pu->free_while_used = 0;
		}
	} else {
		pu_print(pfn, "fail to find", NULL);
	}
	spin_unlock_irqrestore(&page_usage_lock, flags);
}
EXPORT_SYMBOL(dec_page_usage);

bool page_poisoning_enabled(void)
{
	/*
	 * Assumes that debug_pagealloc_enabled is set before
	 * memblock_free_all.
	 * Page poisoning is debug page alloc for some arches. If
	 * either of those options are enabled, enable poisoning.
	 */
	return (want_page_poisoning ||
		(!IS_ENABLED(CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC) &&
		debug_pagealloc_enabled()));
}
EXPORT_SYMBOL_GPL(page_poisoning_enabled);

static void poison_page(struct page *page)
{
	void *addr = kmap_atomic(page);

	if (atomic_read(&page_usage_initialized)) {
		unsigned long pfn = page_to_pfn(page);
		struct page_usage *pu;
		unsigned long flags;

		spin_lock_irqsave(&page_usage_lock, flags);
		pu = xa_load(&page_usage_table, pfn);
		if (pu && pu->count) {
			dump_stack();
			pu_print(pfn, "enter free state when still used", pu);
			pu->free_while_used = 1;
		}
		spin_unlock_irqrestore(&page_usage_lock, flags);
	}

	/* KASAN still think the page is in-use, so skip it. */
	kasan_disable_current();
	memset(addr, PAGE_POISON, PAGE_SIZE);
	kasan_enable_current();
	kunmap_atomic(addr);
}

static void poison_pages(struct page *page, int n)
{
	int i;

	for (i = 0; i < n; i++)
		poison_page(page + i);
}

static bool single_bit_flip(unsigned char a, unsigned char b)
{
	unsigned char error = a ^ b;

	return error && !(error & (error - 1));
}

static void check_poison_mem(unsigned char *mem, size_t bytes)
{
	static DEFINE_RATELIMIT_STATE(ratelimit, 5 * HZ, 10);
	unsigned char *start;
	unsigned char *end;

	if (IS_ENABLED(CONFIG_PAGE_POISONING_NO_SANITY))
		return;

	start = memchr_inv(mem, PAGE_POISON, bytes);
	if (!start)
		return;

	for (end = mem + bytes - 1; end > start; end--) {
		if (*end != PAGE_POISON)
			break;
	}

	if (!__ratelimit(&ratelimit))
		return;
	else if (start == end && single_bit_flip(*start, PAGE_POISON))
		pr_err("pagealloc: single bit error\n");
	else
		pr_err("pagealloc: memory corruption\n");

	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 16, 1, start,
			end - start + 1, 1);
	dump_stack();
}

static void unpoison_page(struct page *page)
{
	void *addr;

	addr = kmap_atomic(page);
	/*
	 * Page poisoning when enabled poisons each and every page
	 * that is freed to buddy. Thus no extra check is done to
	 * see if a page was poisoned.
	 */
	check_poison_mem(addr, PAGE_SIZE);
	kunmap_atomic(addr);
}

static void unpoison_pages(struct page *page, int n)
{
	int i;

	for (i = 0; i < n; i++)
		unpoison_page(page + i);
}

void kernel_poison_pages(struct page *page, int numpages, int enable)
{
	if (!page_poisoning_enabled())
		return;

	if (enable)
		unpoison_pages(page, numpages);
	else
		poison_pages(page, numpages);
}

#ifndef CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	/* This function does nothing, all work is done via poison pages */
}
#endif
