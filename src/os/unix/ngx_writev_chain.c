
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (IOV_MAX > 64)
#define NGX_IOVS  64
#else
#define NGX_IOVS  IOV_MAX
#endif

/* 几段缓存数据的发送函数 */
ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    u_char        *prev;
    ssize_t        n, size, sent;
    off_t          send, prev_send;
    ngx_uint_t     eintr, complete;
    ngx_err_t      err;
    ngx_array_t    vec;
    ngx_chain_t   *cl;
    ngx_event_t   *wev;
    struct iovec  *iov, iovs[NGX_IOVS];

    wev = c->write;

    if (!wev->ready) {//非可写事件，返回
        return in;
    }

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }

    send = 0;
    complete = 0;

    vec.elts = iovs;
    vec.size = sizeof(struct iovec);
    vec.nalloc = NGX_IOVS;
    vec.pool = c->pool;

    for ( ;; ) {
        prev = NULL;
        iov = NULL;
        eintr = 0;
        prev_send = send;

        vec.nelts = 0;

        /* create the iovec and coalesce the neighbouring bufs */

        for (cl = in; cl && vec.nelts < IOV_MAX && send < limit; cl = cl->next)
        {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

#if 1
            if (!ngx_buf_in_memory(cl->buf)) {
                ngx_debug_point();
            }
#endif

            size = cl->buf->last - cl->buf->pos;//计算该段缓存内待发送数据长度

            if (send + size > limit) {//write的数据超出了限制
                size = (ssize_t) (limit - send);
            }

            if (prev == cl->buf->pos) {
                iov->iov_len += size;

            } else {
                iov = ngx_array_push(&vec);//添加到数组中 
                if (iov == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = size;
            }

            prev = cl->buf->pos + size;
            send += size;
        }

        n = writev(c->fd, vec.elts, vec.nelts);//执行writev操作，把几段缓存数据一次内核调用发送出

        if (n == -1) {
            err = ngx_errno;

            switch (err) {
            case NGX_EAGAIN://函数会被阻塞，一般因为写空间不足
                break;

            case NGX_EINTR://被信号中断
                eintr = 1;
                break;

            default://此时写操作出现错误
                wev->error = 1;
                (void) ngx_connection_error(c, err, "writev() failed");
                return NGX_CHAIN_ERROR;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
        }

        sent = n > 0 ? n : 0;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "writev: %z", sent);

        if (send - prev_send == sent) {//此时vec里的数据被全部write完
            complete = 1;
        }

        c->sent += sent;

        for (cl = in; cl; cl = cl->next) {

            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (sent == 0) {
                break;
            }

            size = cl->buf->last - cl->buf->pos;

            if (sent >= size) {
                sent -= size;
                cl->buf->pos = cl->buf->last;

                continue;
            }

            cl->buf->pos += sent;//算出最后一段内存已write的字节数

            break;
        }

        if (eintr) {//如果发生错误，但是因为被信号中断的，继续执行
            continue;
        }

        if (!complete) {//此时写缓存不足，等待下次执行
            wev->ready = 0;
            return cl;
        }

        if (send >= limit || cl == NULL) {
            return cl;
        }

        in = cl;
    }
}
