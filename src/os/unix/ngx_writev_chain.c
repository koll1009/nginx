
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

/* ���λ������ݵķ��ͺ��� */
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

    if (!wev->ready) {//�ǿ�д�¼�������
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

            size = cl->buf->last - cl->buf->pos;//����öλ����ڴ��������ݳ���

            if (send + size > limit) {//write�����ݳ���������
                size = (ssize_t) (limit - send);
            }

            if (prev == cl->buf->pos) {
                iov->iov_len += size;

            } else {
                iov = ngx_array_push(&vec);//��ӵ������� 
                if (iov == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = size;
            }

            prev = cl->buf->pos + size;
            send += size;
        }

        n = writev(c->fd, vec.elts, vec.nelts);//ִ��writev�������Ѽ��λ�������һ���ں˵��÷��ͳ�

        if (n == -1) {
            err = ngx_errno;

            switch (err) {
            case NGX_EAGAIN://�����ᱻ������һ����Ϊд�ռ䲻��
                break;

            case NGX_EINTR://���ź��ж�
                eintr = 1;
                break;

            default://��ʱд�������ִ���
                wev->error = 1;
                (void) ngx_connection_error(c, err, "writev() failed");
                return NGX_CHAIN_ERROR;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
        }

        sent = n > 0 ? n : 0;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "writev: %z", sent);

        if (send - prev_send == sent) {//��ʱvec������ݱ�ȫ��write��
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

            cl->buf->pos += sent;//������һ���ڴ���write���ֽ���

            break;
        }

        if (eintr) {//����������󣬵�����Ϊ���ź��жϵģ�����ִ��
            continue;
        }

        if (!complete) {//��ʱд���治�㣬�ȴ��´�ִ��
            wev->ready = 0;
            return cl;
        }

        if (send >= limit || cl == NULL) {
            return cl;
        }

        in = cl;
    }
}
