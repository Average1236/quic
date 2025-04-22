#ifndef CLIENT_CB_H
#define CLIENT_CB_H
#include <fcntl.h>
#include <inttypes.h>
#include "client.h"

#include <unistd.h>
#include <sys/wait.h>

#define XQC_MAX_BUFF_SIZE 4096

void xqc_mini_cli_datagram_mss_updated_callback(xqc_connection_t *conn, size_t mss, void *user_data);

void xqc_mini_cli_datagram_read_callback(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t dgram_ts);

void xqc_mini_cli_datagram_write_callback(xqc_connection_t *conn, void *user_data);

void xqc_mini_cli_datagram_acked_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);

int xqc_mini_cli_datagram_lost_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);

int xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data);

int xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data);

int xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data);

void xqc_mini_cli_engine_cb(int fd, short what, void *arg);

int xqc_mini_cli_open_log_file(void *arg);
void xqc_mini_cli_close_log_file(void *arg);
void xqc_mini_cli_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);

int xqc_mini_cli_open_keylog_file(void *arg);
void xqc_mini_cli_close_keylog_file(void *arg);

void xqc_mini_cli_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *engine_user_data);

void xqc_mini_cli_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data);

int xqc_mini_cli_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
int xqc_mini_cli_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
void xqc_mini_cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data);

int xqc_mini_cli_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data);
void xqc_mini_cli_h3_request_closing_notify(xqc_h3_request_t *h3_request, 
    xqc_int_t err, void *h3s_user_data);
int xqc_mini_cli_h3_request_close_notify(xqc_h3_request_t *h3_request, void *user_data);
int xqc_mini_cli_h3_request_read_notify(xqc_h3_request_t *h3_request, 
    xqc_request_notify_flag_t flag, void *h3s_user_data);
int xqc_mini_cli_h3_request_write_notify(xqc_h3_request_t *h3_request, void *h3s_user_data);

void xqc_mini_cli_set_event_timer(xqc_usec_t wake_after, void *user_data);

ssize_t xqc_mini_cli_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data);

ssize_t xqc_mini_cli_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);

int xqc_mini_cli_read_token(unsigned char *token, unsigned token_len);

void xqc_mini_cli_save_token(const unsigned char *token, unsigned token_len, void *user_data);

void xqc_mini_cli_save_session_cb(const char * data, size_t data_len, void *user_data);

void xqc_mini_cli_save_tp_cb(const char * data, size_t data_len, void * user_data);

void xqc_mini_cli_timeout_callback(int fd, short what, void *arg);

int xqc_mini_cli_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);

int xqc_mini_cli_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);

void xqc_mini_cli_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data);

void xqc_mini_cli_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data);

#endif