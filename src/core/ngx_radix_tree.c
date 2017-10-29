
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_radix_alloc(ngx_radix_tree_t *tree);


/* 新建一个基数树，@preallocate为预分配的结点数 */
ngx_radix_tree_t *
ngx_radix_tree_create(ngx_pool_t *pool, ngx_int_t preallocate)
{
    uint32_t           key, mask, inc;
    ngx_radix_tree_t  *tree;

    tree = ngx_palloc(pool, sizeof(ngx_radix_tree_t));
    if (tree == NULL) {
        return NULL;
    }

    tree->pool = pool;
    tree->free = NULL;
    tree->start = NULL;
    tree->size = 0;

    tree->root = ngx_radix_alloc(tree);//创建根节点
    if (tree->root == NULL) {
        return NULL;
    }

    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->parent = NULL;
    tree->root->value = NGX_RADIX_NO_VALUE;

    if (preallocate == 0) {
        return tree;
    }

    /*
     * Preallocation of first nodes : 0, 1, 00, 01, 10, 11, 000, 001, etc.
     * increases TLB hits even if for first lookup iterations.
     * On 32-bit platforms the 7 preallocated bits takes continuous 4K,
     * 8 - 8K, 9 - 16K, etc.  On 64-bit platforms the 6 preallocated bits
     * takes continuous 4K, 7 - 8K, 8 - 16K, etc.  There is no sense to
     * to preallocate more than one page, because further preallocation
     * distributes the only bit per page.  Instead, a random insertion
     * may distribute several bits per page.
     *
     * Thus, by default we preallocate maximum
     *     6 bits on amd64 (64-bit platform and 4K pages)
     *     7 bits on i386 (32-bit platform and 4K pages)
     *     7 bits on sparc64 in 64-bit mode (8K pages)
     *     8 bits on sparc64 in 32-bit mode (8K pages)
     */

    if (preallocate == -1) {/* 此时按照一个内存页预分配 */
        switch (ngx_pagesize / sizeof(ngx_radix_tree_t)) {
	    /* 对于掩码mask，从高位开始每一位表示2^n个结点，所以掩码表示的结点总数为2^1+2^2...+2^n=2^(n+1)-2,
		 * 加上根结点，总数为2^(n+1)-1，所以preallocate的取值比case的右移1位
		 */
        /* amd64 */
        case 128:
            preallocate = 6;
            break;

        /* i386, sparc64 */
        case 256:
            preallocate = 7;
            break;

        /* sparc64 in 32-bit mode */
        default:
            preallocate = 8;
        }
    }

    mask = 0;
    inc = 0x80000000;

    while (preallocate--) {//逐层挨个分配结点

        key = 0;
        mask >>= 1;
        mask |= 0x80000000;

        do {
            if (ngx_radix32tree_insert(tree, key, mask, NGX_RADIX_NO_VALUE)
                != NGX_OK)
            {
                return NULL;
            }

            key += inc;

        } while (key);

        inc >>= 1;
    }

    return tree;
}


/* 基数树插入一个结点 */
ngx_int_t
ngx_radix32tree_insert(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask,
    uintptr_t value)
{
    uint32_t           bit;
    ngx_radix_node_t  *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    /* 检测该结点是否已经分配内存 */
    while (bit & mask) {
        if (key & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        if (next == NULL) {
            break;
        }

        bit >>= 1;
        node = next;
    }

    if (next) {/* 该结点已经分配，直接使用 */
        if (node->value != NGX_RADIX_NO_VALUE) {//此时，该结点已经被占用
            return NGX_BUSY;
        }

        node->value = value;
        return NGX_OK;
    }

    while (bit & mask) {/* 把该key值尚未分配内存的结点新分配内存 */
        next = ngx_radix_alloc(tree);
        if (next == NULL) {
            return NGX_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = NGX_RADIX_NO_VALUE;

        if (key & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return NGX_OK;
}

/* 基数树删除一个结点 */
ngx_int_t
ngx_radix32tree_delete(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask)
{
    uint32_t           bit;
    ngx_radix_node_t  *node;

    bit = 0x80000000;
    node = tree->root;

    while (node && (bit & mask)) {
        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    if (node == NULL) {
        return NGX_ERROR;
    }

    if (node->right || node->left) {//删除一个中间结点
        if (node->value != NGX_RADIX_NO_VALUE) {
            node->value = NGX_RADIX_NO_VALUE;
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    for ( ;; ) {/* 删除结点，如果父结点只有此子结点且无值，一并删除 */
        if (node->parent->right == node) {
            node->parent->right = NULL;

        } else {
            node->parent->left = NULL;
        }

        node->right = tree->free;/* 把删除的结点挂入空闲链 */
        tree->free = node;

        node = node->parent;
		/* 父结点无其余子结点，无有意义值，且不为根结点，一并删除 */
        if (node->right || node->left) {
            break;
        }

        if (node->value != NGX_RADIX_NO_VALUE) {
            break;
        }

        if (node->parent == NULL) {
            break;
        }
    }

    return NGX_OK;
}


/* 基数树查找操作 */
uintptr_t
ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key)
{
    uint32_t           bit;
    uintptr_t          value;
    ngx_radix_node_t  *node;

    bit = 0x80000000;
    value = NGX_RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    return value;
}


/* 分配一个基数树结点 */
static void *
ngx_radix_alloc(ngx_radix_tree_t *tree)
{
    char  *p;

    if (tree->free) {//有空闲结点，则取第一个
        p = (char *) tree->free;
        tree->free = tree->free->right;
        return p;
    }

    if (tree->size < sizeof(ngx_radix_node_t)) {//无空闲内存，则新分配一页内存
        tree->start = ngx_pmemalign(tree->pool, ngx_pagesize, ngx_pagesize);
        if (tree->start == NULL) {
            return NULL;
        }

        tree->size = ngx_pagesize;
    }

    p = tree->start;
    tree->start += sizeof(ngx_radix_node_t);
    tree->size -= sizeof(ngx_radix_node_t);

    return p;
}
