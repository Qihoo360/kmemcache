#ifndef __MC_BUFFER_H
#define __MC_BUFFER_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#ifdef CONFIG_X86_32
#define GFP_PAGES (GFP_KERNEL | __GFP_HIGHMEM)
#else
#define GFP_PAGES GFP_KERNEL
#endif

#define BUF_NEGATIVE	0
#define BUF_KMALLOC	1
#define BUF_VMALLOC	2
#define BUF_PAGES	3
#define BUF_FLAGS_MAX	4

#define BUF_KMALLOC_MAX	PAGE_SIZE
#define BUF_PAGES_MAX	1024 * 1024	/* 1M */

struct buffer {
	/*
	 * BUF_NEGATIVE: not alloced
	 * BUF_KMALLOC : kmalloc
	 * BUF_VMALLOC : vmalloc
	 * BUF_PAGES   : alloc_pages
	 */
	unsigned int flags: 3;

	/*
	 * for kmalloc, ksize(p)
	 * for alloc_pages, bytes size
	 * for vmalloc, request size
	 */
	unsigned int room: 29;

	void *buf;
#ifdef CONFIG_X86_32
	struct page *_page;
#endif
};

#ifdef CONFIG_X86_32
#define __INIT_BUFFER(buf) {			\
	.flags	= BUF_NEGATIVE,			\
	.room	= 0,				\
	.buf	= NULL,				\
	._page	= NULL }
#else
#define __INIT_BUFFER(buf) {			\
	.flags	= BUF_NEGATIVE,			\
	.room	= 0,				\
	.buf	= NULL }

#endif

#define DECLEARE_BUFFER(name)			\
	struct buffer name = __INIT_BUFFER(name)

#define init_buffer(buf)			\
	do {					\
		memset((buf), 0, sizeof(*(buf)));\
	} while (0)

#define BUFFER(b)			\
({					\
 	void *_buf;			\
 	switch ((b)->flags) {		\
 	case BUF_KMALLOC:		\
 	case BUF_VMALLOC:		\
 	case BUF_PAGES:			\
 		_buf = (b)->buf;	\
 		break;			\
 	default:			\
 		BUG();			\
 		break;			\
 	}				\
 	_buf;				\
})

#define BUFFER_PTR(buf, ptr)			\
	do {					\
		void *_buf;			\
		_buf = BUFFER(buf);		\
		(ptr) = (typeof(*(ptr)) *)_buf;	\
	} while (0)

/**
 * alloc_buffer() - wapper of kmalloc/vmalloc/pages
 * @buf		: !null
 * @len		: request buffer size
 * @mask	: gfp mask
 * 
 * return 0 success, errno otherwise
 */
extern int alloc_buffer(struct buffer *buf, size_t len, gfp_t mask);

/**
 * realloc_buffer() - realloc buffer or alloc new buffer, dumping on buffer's flags
 * @buf		: !null
 * @len		: request new size, greater or less than previous size
 * @mask	: gfp mask
 * 
 * return 0 success, errno otherwise
 */
extern int realloc_buffer(struct buffer *buf, size_t len, size_t valid, gfp_t mask);

extern void free_buffer(struct buffer *buf);
extern void free_buffer_init(struct buffer *buf);

#endif /* __MC_BUFFER_H */
