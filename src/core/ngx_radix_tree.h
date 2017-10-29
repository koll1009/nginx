
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RADIX_TREE_H_INCLUDED_
#define _NGX_RADIX_TREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct ngx_radix_node_s  ngx_radix_node_t;

/* 基数树结点结构体 */
struct ngx_radix_node_s {
    ngx_radix_node_t  *right;
    ngx_radix_node_t  *left;
    ngx_radix_node_t  *parent;
    uintptr_t          value;//值，可以为指针
};


/* 基数树结构体 */
typedef struct {
    ngx_radix_node_t  *root;//根节点
    ngx_pool_t        *pool;//内存池
    ngx_radix_node_t  *free;//空闲结点，使用right指针连接
    char              *start;
    size_t             size;
} ngx_radix_tree_t;


ngx_radix_tree_t *ngx_radix_tree_create(ngx_pool_t *pool,
    ngx_int_t preallocate);
ngx_int_t ngx_radix32tree_insert(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
ngx_int_t ngx_radix32tree_delete(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key);


#endif /* _NGX_RADIX_TREE_H_INCLUDED_ */
