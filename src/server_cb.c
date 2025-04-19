/**
 * @file mini_server_cb.c contains callbacks definitions for mini_server, including:
 * 1. engine callbacks
 * 2. hq callbacks
 * 3. h3 callbacks
 */

#include "server_cb.h"
/* engine callbacks */


static const char *line_break = "\n";

void 
xqc_mini_svr_datagram_mss_updated_callback(xqc_connection_t *conn, 
    size_t mss, void *user_data)
{
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)user_data;
    if (user_conn->dgram_mss == 0) {
        printf("[dgram]|1RTT|initial_mss:%zu|\n", mss);

    } else {
        printf("[dgram]|1RTT|updated_mss:%zu|\n", mss);
    }

    user_conn->dgram_mss = mss;

    if (!user_conn->dgram_not_supported && user_conn->dgram_mss == 0) {
        user_conn->dgram_not_supported = 1;
    }
}

void
xqc_mini_svr_datagram_read_callback(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t dgram_ts)
{
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)user_data;

    if (user_conn->dgram_send_multiple) {
        if (user_conn->echo) {
            uint64_t dgram_id;
            int ret;
            if (user_conn->dgram_blk->data_recv + data_len > user_conn->dgram_blk->data_len) {
                //expand buffer size
                size_t new_len = (user_conn->dgram_blk->data_recv + data_len) << 1;
                unsigned char *new_data = calloc(1, new_len);
                memcpy(new_data, user_conn->dgram_blk->data, user_conn->dgram_blk->data_recv);
                if (user_conn->dgram_blk->data) {
                    free(user_conn->dgram_blk->data);
                }
                user_conn->dgram_blk->data = new_data;
                user_conn->dgram_blk->data_len = new_len;
            }
            memcpy(user_conn->dgram_blk->data + user_conn->dgram_blk->data_recv, data, data_len);
            user_conn->dgram_blk->data_recv += data_len;
            user_conn->dgram_blk->to_send_size = user_conn->dgram_blk->data_recv;
            
        } else {
            user_conn->dgram_blk->data_recv += data_len;
        }
    }

    if (user_conn->dgram_send_multiple){
        if (user_conn->dgram_blk->data_sent < user_conn->dgram_blk->data_len) {
           xqc_mini_svr_datagram_send(user_conn); 
        }
    }
}

void
xqc_mini_svr_datagram_write_callback(xqc_connection_t *conn, void *user_data)
{
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)user_data;
    if (user_conn->dgram_send_multiple) {
        xqc_mini_svr_datagram_send(user_conn);
    }
}

void
xqc_mini_svr_datagram_acked_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    
}

int
xqc_mini_svr_datagram_lost_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)user_data;
    user_conn->dgram_blk->dgram_lost++;
    return 0;
}

int
xqc_mini_svr_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)user_data;

    user_conn->quic_conn = conn;
    user_conn->dgram_blk = calloc(1, sizeof(user_dgram_blk_t));
    user_conn->dgram_blk->data_recv = 0;
    user_conn->dgram_blk->data_sent = 0;
    
    xqc_datagram_set_user_data(conn, user_conn);

    if (user_conn->dgram_send_multiple) {
        user_conn->dgram_blk->data = calloc(1, user_conn->send_body_size);
        user_conn->dgram_blk->data_len = user_conn->send_body_size;
        if (!user_conn->echo) {
            user_conn->dgram_blk->to_send_size = user_conn->send_body_size;
        }
    }

    return 0;
}

int
xqc_mini_svr_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, lost_dgram_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s, alpn:%s\n",
           stats.send_count, stats.lost_count, stats.lost_dgram_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info, stats.alpn);

    printf("[dgram]|recv_dgram_bytes:%zu|sent_dgram_bytes:%zu|lost_dgram_bytes:%zu|lost_cnt:%zu|\n", 
           user_conn->dgram_blk->data_recv, user_conn->dgram_blk->data_sent,
           user_conn->dgram_blk->data_lost, user_conn->dgram_blk->dgram_lost);

    if (user_conn->dgram_blk) {
        if (user_conn->dgram_blk->data) {
            free(user_conn->dgram_blk->data);
        }
        free(user_conn->dgram_blk);
    }

    free(user_conn);

    if (user_conn->mpshell) {
        event_base_loopbreak(user_conn->ctx->eb);
        printf("xqc_server_conn_close_notify\n");
    }

    return 0;
}

void
xqc_mini_svr_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *) user_data;
    printf("datagram_mss:%zd\n", xqc_datagram_get_mss(conn));
}

void
xqc_mini_svr_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(user_conn->ctx->engine, retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(user_conn->ctx->engine, new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(user_conn->ctx->engine, new_cid));

}

int
xqc_mini_svr_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    int ret = 0;

    xqc_mini_svr_user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->stream = stream;
    xqc_stream_set_user_data(stream, user_stream);

    return 0;
}

int
xqc_mini_svr_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int
xqc_mini_svr_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    return 0;
}

int
xqc_mini_svr_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    return 0;
}


/**
 * @brief engine callbacks to trigger engine main logic 
 */
void
xqc_mini_svr_engine_cb(int fd, short what, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

/**
 * @brief callbacks to set timer of engine callbacks
 */
void
xqc_mini_svr_set_event_timer(xqc_msec_t wake_after, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t *)arg;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

int
xqc_mini_svr_open_log_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    return open(ctx->args->env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}
void
xqc_mini_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->log_fd <= 0) {
        return;
    }

    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_sys_errno());
    }
}


void
xqc_mini_svr_close_log_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->log_fd > 0) {
        close(ctx->log_fd);
        ctx->log_fd = 0;
    }
}

void
xqc_mini_svr_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->log_fd <= 0) {
        return;
    }

    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", get_sys_errno());
    }
}

int
xqc_mini_svr_open_keylog_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    return open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}

void
xqc_mini_svr_keylog_cb(const xqc_cid_t *scid, const char *line, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->keylog_fd, line_break, 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
    }
}

void
xqc_mini_svr_close_keylog_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->keylog_fd > 0) {
        close(ctx->keylog_fd);
        ctx->keylog_fd = 0;
    }
}
int
xqc_mini_svr_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *arg)
{
    DEBUG;

    return 0;
}


ssize_t 
xqc_mini_svr_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *arg)
{
    ssize_t res = XQC_OK;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)arg;
    int fd = user_conn->ctx->current_fd;

    do {
        set_sys_errno(0);
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("[error] xqc_mini_svr_write_socket err %zd %s, fd: %d\n", 
                res, strerror(get_sys_errno()), fd);
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    // printf("[report] xqc_mini_svr_write_socket success size=%lu\n", size);
    return res;
}

ssize_t
xqc_mini_svr_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size, 
    const struct sockaddr *peer_addr,socklen_t peer_addrlen, void *conn_user_data)
{
    return xqc_mini_svr_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

/* h3 callbacks */
int
xqc_mini_svr_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)conn_user_data;
    xqc_h3_conn_set_user_data(h3_conn, user_conn);
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)user_conn->peer_addr,
                              sizeof(struct sockaddr_in), &user_conn->peer_addrlen);
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    printf("[stats] xqc_mini_svr_h3_conn_create_notify \n");
    return 0;
}


int
xqc_mini_svr_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)conn_user_data;
    
    printf("[stats] xqc_mini_svr_h3_conn_close_notify success \n");
    return 0;
}


void 
xqc_mini_svr_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
}


int
xqc_mini_svr_h3_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t *)calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;

    xqc_h3_request_set_user_data(h3_request, user_stream);
    user_stream->recv_buf = (char *)calloc(1, REQ_BUF_SIZE);

    printf("[stats] xqc_mini_svr_h3_request_create_notify success \n");
    return 0;
}

int
xqc_mini_svr_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);
    printf("[stats] xqc_mini_svr_h3_request_close_notify success, cwnd_blocked:%"PRIu64"\n", stats.cwnd_blocked_ms);

    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t*)strm_user_data;
    free(user_stream);

    return 0;
}
int
xqc_mini_cli_handle_h3_request(xqc_mini_svr_user_stream_t *user_stream)
{
    DEBUG;
    ssize_t ret = 0;

    /* response header buf list */
    xqc_http_header_t rsp_hdr[] = {
        {
            .name = {.iov_base = "content-type", .iov_len = 12},
            .value = {.iov_base = "text/plain", .iov_len = 10},
            .flags = 0,
        }
    };
    /* response header */
    xqc_http_headers_t rsp_hdrs;
    rsp_hdrs.headers = rsp_hdr;
    rsp_hdrs.count = sizeof(rsp_hdr) / sizeof(rsp_hdr[0]);

    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(user_stream->h3_request, &rsp_hdrs, 0);
        if (ret < 0) {
            printf("[error] xqc_h3_request_send_headers error %zd\n", ret);
            return ret;
        } else {
            printf("[stats] xqc_h3_request_send_headers success \n");
            user_stream->header_sent = 1;
        }
    }

    ret = xqc_mini_svr_send_body(user_stream);
    return ret;
}

int
xqc_mini_svr_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    DEBUG;
    int ret;
    char recv_buff[4096] = {0};
    ssize_t recv_buff_size, read, read_sum;
    unsigned char fin = 0;
    xqc_http_headers_t *headers = NULL;
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t *)strm_user_data;

    read = read_sum = 0;
    recv_buff_size = 4096;

    /* recv headers */
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("[error] xqc_h3_request_recv_headers error\n");
            return XQC_ERROR;
        }

        /* TODO: if recv headers once for all? */
        user_stream->header_recvd = 1;

    } else if (flag & XQC_REQ_NOTIFY_READ_BODY) {   /* recv body */
        do {
            read = xqc_h3_request_recv_body(h3_request, (unsigned char *)recv_buff, recv_buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;

            } else if (read < 0) {
                printf("[error] xqc_h3_request_recv_body error %zd\n", read);
                return XQC_OK;
            }

            read_sum += read;
            user_stream->recv_body_len += read;
        } while (read > 0 && !fin);
    }
    if (fin) {
        printf("[stats] read h3 request finish. \n");
        xqc_mini_cli_handle_h3_request(user_stream);
    }
    return 0;
}

int
xqc_mini_svr_send_body(xqc_mini_svr_user_stream_t *user_stream)
{
    int fin = 1, send_buf_size, ret;
    char send_buf[REQ_BUF_SIZE];

    send_buf_size = REQ_BUF_SIZE;
    memset(send_buf, 'D', send_buf_size);

    ret = xqc_h3_request_send_body(user_stream->h3_request, (unsigned char *)send_buf, send_buf_size, fin);
    
    printf("[reports] xqc_mini_svr_send_body success, size:%d \n", ret);
    return ret;
}

int
xqc_mini_svr_h3_request_write_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t *)strm_user_data;
    int ret = xqc_mini_svr_send_body(user_stream);

    printf("[stats] write h3 request notify finish \n");
    return ret;
}
