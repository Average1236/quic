#ifndef SERVER_CB_H
#define SERVER_CB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include "xquic_typedef.h"

#include <unistd.h>
#include <sys/wait.h>

#include "server.h"
#include <inttypes.h>

#define REQ_BUF_SIZE 2048

typedef struct xqc_mini_svr_user_stream_s {
    xqc_stream_t                *stream;
    xqc_h3_request_t           *h3_request;

    // uint64_t            send_offset;
    int                         header_sent;
    int                         header_recvd;
    char                    *send_body;
    size_t                   send_body_len;
    size_t                   send_body_max;
    char                    *recv_body;
    size_t                   recv_body_len;
    FILE                    *recv_body_fp;
    char                       *recv_buf;
} xqc_mini_svr_user_stream_t;

/* datagram callbacks */
void xqc_mini_svr_datagram_acked_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);

int xqc_mini_svr_datagram_lost_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);

void xqc_mini_svr_datagram_mss_updated_callback(xqc_connection_t *conn, size_t mss, void *user_data);

void xqc_mini_svr_datagram_read_callback(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t dgram_ts);

void xqc_mini_svr_datagram_write_callback(xqc_connection_t *conn, void *user_data);

int xqc_mini_svr_stream_create_notify(xqc_stream_t *stream, void *user_data);

int xqc_mini_svr_stream_close_notify(xqc_stream_t *stream, void *user_data);

int xqc_mini_svr_stream_write_notify(xqc_stream_t *stream, void *user_data);

int xqc_mini_svr_stream_read_notify(xqc_stream_t *stream, void *user_data);

int xqc_mini_svr_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);

int xqc_mini_svr_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);

void xqc_mini_svr_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data);

void xqc_mini_svr_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data);


/* engine callbacks */
void xqc_mini_svr_engine_cb(int fd, short what, void *arg);

void xqc_mini_svr_set_event_timer(xqc_msec_t wake_after, void *arg);

int xqc_mini_svr_open_log_file(void *arg);

void xqc_mini_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *arg);

void xqc_mini_svr_close_log_file(void *arg);

void xqc_mini_svr_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *arg);

int xqc_mini_svr_open_keylog_file(void *arg);

void xqc_mini_svr_keylog_cb(const xqc_cid_t *scid, const char *line, void *arg);

void xqc_mini_svr_close_keylog_file(void *arg);

int xqc_mini_svr_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *eng_user_data);

ssize_t xqc_mini_svr_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *arg);

ssize_t xqc_mini_svr_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size, 
    const struct sockaddr *peer_addr,socklen_t peer_addrlen, void *arg);

void xqc_mini_svr_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *user_data);

/* h3 callbacks */
int xqc_mini_svr_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data);

int xqc_mini_svr_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data);

void xqc_mini_svr_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data);

int xqc_mini_svr_h3_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data);

int xqc_mini_svr_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data);

int xqc_mini_svr_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data);

int xqc_mini_svr_h3_request_write_notify(xqc_h3_request_t *h3_request, void *strm_user_data);

int xqc_mini_svr_send_body(xqc_mini_svr_user_stream_t *user_stream);

#ifdef __cplusplus
}
#endif
#endif
