/**
 * @file mini_server_cb.c contains callbacks definitions for mini_server, including:
 * 1. engine callbacks
 * 2. hq callbacks
 * 3. h3 callbacks
 */
#include "client_cb.h"
/**
 * @brief engine callbacks to trigger engine main logic 
 */
static const char *line_break = "\n";

void
xqc_mini_cli_datagram_mss_updated_callback(xqc_connection_t *conn, size_t mss, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t*)user_data;
    user_conn->dgram_mss = mss;
    printf("[dgram]|mss_callback|updated_mss:%zu|\n", mss);
}

void
xqc_mini_cli_datagram_read_callback(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t dgram_ts)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t*)user_data;
    user_conn->dgram_blk->data_recv += data_len;
    //printf("[dgram]|read_data|size:%zu|recv_time:%"PRIu64"|\n", data_len, dgram_ts);
}

void
xqc_mini_cli_datagram_write_callback(xqc_connection_t *conn, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t*)user_data;
    if (user_conn->dgram_send_multiple) {
        printf("[dgram]|dgram_write|\n");
        xqc_mini_cli_datagram_send(user_conn);
    }
}

void
xqc_mini_cli_datagram_acked_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t*)user_data;
    printf("[dgram]|dgram_acked|dgram_id:%"PRIu64"|\n", dgram_id);
}

int
xqc_mini_cli_datagram_lost_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t*)user_data;
    user_conn->dgram_blk->dgram_lost++;
    printf("[dgram]|dgram_lost|dgram_id:%"PRIu64"|\n", dgram_id);
    return 0;
}

int
xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    return 0;
}

int
xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    return 0;
}

int
xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    return 0;
}

void
xqc_mini_cli_engine_cb(int fd, short what, void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

int
xqc_mini_cli_open_log_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    return open(ctx->args->env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}

void
xqc_mini_cli_close_log_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    if (ctx->log_fd > 0) {
        close(ctx->log_fd);
        ctx->log_fd = 0;
    }
}

void
xqc_mini_cli_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }
    //printf("%s", (char *)buf);
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


int
xqc_mini_cli_open_keylog_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    return open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}

void
xqc_mini_cli_close_keylog_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    if (ctx->keylog_fd > 0) {
        close(ctx->keylog_fd);
        ctx->keylog_fd = 0;
    }
}

void
xqc_mini_cli_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *engine_user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)engine_user_data;
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


void
xqc_mini_cli_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)engine_user_data;

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
int
xqc_mini_cli_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;

    user_conn->h3_conn = conn;
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));

    return XQC_OK;
}

int
xqc_mini_cli_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;

    event_base_loopbreak(user_conn->ctx->eb);
    printf("[stats] xqc_mini_cli_h3_conn_close_notify success \n");
    return XQC_OK;
}

void
xqc_mini_cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    return;
}
int
xqc_mini_cli_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    return 0;
}

int
xqc_mini_cli_h3_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    xqc_mini_cli_user_stream_t *user_stream = (xqc_mini_cli_user_stream_t *)user_data;
    xqc_mini_cli_user_conn_t *user_conn = user_stream->user_conn;
    xqc_mini_cli_ctx_t *conn_ctx = user_conn->ctx;
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);

    xqc_h3_conn_close(conn_ctx->engine, &user_conn->cid);
    free(user_stream);

    printf("[stats] xqc_mini_cli_h3_request_close_notify success, cwnd_blocked:%"PRIu64"\n", stats.cwnd_blocked_ms);
    return 0;
}
int
xqc_mini_cli_h3_request_read_notify(xqc_h3_request_t *h3_request, 
    xqc_request_notify_flag_t flag, void *h3s_user_data)
{
    char recv_buff[XQC_MAX_BUFF_SIZE] = {0};
    size_t recv_buff_size;
    ssize_t read, read_sum;
    unsigned char fin = 0;
    xqc_mini_cli_user_stream_t *user_stream = (xqc_mini_cli_user_stream_t *)h3s_user_data;
    xqc_mini_cli_user_conn_t *user_conn = user_stream->user_conn;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("[error] xqc_h3_request_recv_headers error\n");
            return XQC_ERROR;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("[receive report] %s = %s\n", (char *)headers->headers[i].name.iov_base,
                (char *)headers->headers[i].value.iov_base);
        }

        if (fin) {
            /* only header in request */
            user_stream->recv_fin = 1;
            printf("[stats] h3 request read header finish \n");
            return XQC_OK;
        }
    }

    /* continue to recv body */
    if (!(flag & XQC_REQ_NOTIFY_READ_BODY)) {
        return XQC_OK;
    }

    recv_buff_size = XQC_MAX_BUFF_SIZE;
    read = read_sum = 0;

    do {
        read = xqc_h3_request_recv_body(h3_request, recv_buff, recv_buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_h3_request_recv_body error %zd\n", read);
            return XQC_OK;
        }
    
        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    printf("[report] xqc_h3_request_recv_body size %zd, fin:%d\n", read, fin);

    if (fin) {
        printf("[stats] read h3 request finish. \n");
    }

    return XQC_OK;
}

int
xqc_mini_cli_h3_request_write_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    int ret = 0;
    xqc_mini_cli_user_stream_t *user_stream = (xqc_mini_cli_user_stream_t *)h3s_user_data;

    ret = xqc_mini_cli_request_send(h3_request, user_stream);
    
    printf("[stats] finish h3 request write notify!:%"PRIu64"\n", xqc_h3_stream_id(h3_request));
    
    return ret;
}

void
xqc_mini_cli_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, xqc_now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

ssize_t
xqc_mini_cli_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    return xqc_mini_cli_write_socket_ex(0, buf, size, peer_addr, peer_addrlen, conn_user_data);
}

ssize_t
xqc_mini_cli_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    int fd;
    ssize_t res;
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)conn_user_data;
    
    fd = user_conn->fd;
    res = 0;
    
    do {
        set_sys_errno(0);
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_mini_cli_write_socket err %zd %s, fd: %d, buf: %p, size: %zu, "
                "server_addr: %s\n", res, strerror(get_sys_errno()), fd, buf, size,
                user_conn->peer_addr->sa_data);
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    // printf("[report] xqc_mini_cli_write_socket_ex success size=%lu\n", size);

    return res;
}

int
xqc_mini_cli_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open(TOKEN_FILE, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    close(fd);
    return n;
}

void
xqc_mini_cli_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;
    printf("[stats] start xqc_mini_cli_save_token, use client ip as the key.\n");

    int fd = open(TOKEN_FILE, O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
}

void
xqc_mini_cli_save_session_cb(const char * data, size_t data_len, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;
    printf("[stats] start save_session_cb. \n");

    FILE * fp  = fopen(SESSION_TICKET_FILE, "wb");
    if (fp < 0) {
        printf("save session error %s\n", strerror(get_sys_errno()));
        return;
    }

    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void
xqc_mini_cli_save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;
    printf("[stats] start save_tp_cb\n");

    FILE * fp = fopen(TRANSPORT_PARAMS_FILE, "wb");
    if (fp < 0) {
        printf("save transport callback error %s\n", strerror(get_sys_errno()));
        return;
    }

    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }

    fclose(fp);
    return;
}


void
xqc_mini_cli_timeout_callback(int fd, short what, void *arg)
{
    int conn_timeout, last_socket_time, ret;
    xqc_usec_t socket_idle_time;
    struct timeval tv;
    xqc_mini_cli_ctx_t *ctx;
    xqc_mini_cli_user_conn_t *user_conn;

    user_conn = (xqc_mini_cli_user_conn_t *)arg;
    ctx = user_conn->ctx;
    conn_timeout = ctx->args->net_cfg.conn_timeout;
    last_socket_time = ctx->args->net_cfg.last_socket_time;
    socket_idle_time = xqc_now() - last_socket_time;

    if (socket_idle_time < conn_timeout * 1000000) {
        tv.tv_sec = conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        return;
    }

conn_close:
    printf("[stats] client process timeout, connection closing... \n");
    ret = xqc_h3_conn_close(ctx->engine, &user_conn->cid);
    if (ret) {
        printf("[error] xqc_conn_close error:%d\n", ret);
        return;
    }
}

int
xqc_mini_cli_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *) user_data;
    xqc_conn_set_alp_user_data(conn, user_conn);

    printf("[stats] xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return XQC_OK;
}

int
xqc_mini_cli_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;

    xqc_mini_cli_ctx_t *p_ctx;
    p_ctx = user_conn->ctx;

    xqc_int_t err = xqc_conn_get_errno(conn);
    printf("should_clear_0rtt_ticket, conn_err:%d, clear_0rtt_ticket:%d\n", err, xqc_conn_should_clear_0rtt_ticket(err));

    xqc_conn_stats_t stats = xqc_conn_get_stats(p_ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, mp_state:%d, ack_info:%s, alpn:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.mp_state, stats.ack_info, stats.alpn);

    printf("conn_info: \"%s\"\n", stats.conn_info);

    printf("[dgram]|recv_dgram_bytes:%zu|sent_dgram_bytes:%zu|lost_dgram_bytes:%zu|lost_cnt:%zu|\n", 
            user_conn->dgram_blk->data_recv, user_conn->dgram_blk->data_sent,
            user_conn->dgram_blk->data_lost, user_conn->dgram_blk->dgram_lost);


        if (p_ctx->cur_conn_num == 0) {
            event_base_loopbreak(p_ctx->eb);
        }

    return 0;
}

void
xqc_mini_cli_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("====>ping_id:%d\n", *(int *) ping_user_data);

    } else {
        printf("====>no ping_id\n");
    }
}

void
xqc_mini_cli_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *) user_data;
        // if (!g_mp_ping_on) {
        //     xqc_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
        //     xqc_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);
        // }  

    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(user_conn->ctx->engine, &user_conn->cid));
    printf("====>SCID:%s\n", xqc_scid_str(user_conn->ctx->engine, &user_conn->cid));

    user_conn->hsk_completed = 1;

    user_conn->dgram_mss = xqc_datagram_get_mss(conn);
    if (user_conn->dgram_mss == 0) {
        user_conn->dgram_not_supported = 1; 
    }
    
    printf("[dgram-200]|1RTT|updated_mss:%zu|\n", user_conn->dgram_mss);
    
    if (user_conn->dgram_send_multiple && user_conn->dgram_retry_in_hs_cb) {
        xqc_mini_cli_datagram_send(user_conn);
    }
}
