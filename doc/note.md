要在服务器端向指定的客户端发送数据，可以采用以下两种主要方法：

1. **通过 HTTP/3 响应发送数据**：在处理客户端请求时，使用 HTTP/3 的 API 发送响应数据。
2. **使用 QUIC 数据报（Datagram）主动发送数据**：在不依赖客户端请求的情况下，主动向客户端发送数据。

下面将详细介绍这两种方法，并提供相应的代码示例。

---

## 方法一：通过 HTTP/3 响应发送数据

如果您的服务器主要通过 HTTP/3 协议与客户端通信，可以在处理客户端请求时，通过发送响应头和响应体来向客户端发送数据。以下是实现步骤：

### 步骤1：处理客户端的 HTTP/3 请求

在 `src/mini/mini_server_cb.c` 文件中，已经实现了 `xqc_mini_svr_h3_request_read_notify` 回调函数，用于处理客户端的请求数据。当请求数据读取完成后，可以通过该回调函数发送响应数据。

### 步骤2：发送响应头和响应体

在 `xqc_mini_svr_h3_request_read_notify` 回调函数中，使用 `xqc_h3_request_send_headers` 发送响应头，使用 `xqc_h3_request_send_body` 发送响应体。例如：

```c
int
xqc_mini_svr_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t *)strm_user_data;

    // 判断是否完成了请求的读取
    if (flag & XQC_REQ_NOTIFY_READ_ALL) {
        // 定义响应头
        xqc_http_header_t rsp_hdr[] = {
            {
                .name = {.iov_base = "content-type", .iov_len = 12},
                .value = {.iov_base = "text/plain", .iov_len = 10},
                .flags = 0,
            }
        };
        xqc_http_headers_t rsp_hdrs;
        rsp_hdrs.headers = rsp_hdr;
        rsp_hdrs.count = sizeof(rsp_hdr) / sizeof(rsp_hdr[0]);

        // 发送响应头
        ssize_t ret = xqc_h3_request_send_headers(h3_request, &rsp_hdrs, 0);
        if (ret < 0) {
            printf("[error] xqc_h3_request_send_headers error %zd\n", ret);
            return ret;
        }

        // 定义响应体
        const unsigned char* response_body = "Hello, client via HTTP/3!";
        ret = xqc_h3_request_send_body(h3_request, response_body, strlen((const char*)response_body), 1);
        if (ret < 0) {
            printf("[error] xqc_h3_request_send_body error %zd\n", ret);
            return ret;
        }

        printf("[info] Sent HTTP/3 response to client.\n");
    }

    return 0;
}
```

### 说明

- **发送响应头**：使用 `xqc_h3_request_send_headers` 函数发送响应头。需要构造 `xqc_http_headers_t` 结构体，包含响应头的名称和值。
- **发送响应体**：使用 `xqc_h3_request_send_body` 函数发送响应体数据。`fin` 参数设置为 `1`，表示响应体发送完毕。

---

## 方法二：使用 QUIC 数据报（Datagram）主动发送数据

如果需要在不依赖客户端请求的情况下，主动向客户端发送数据，可以使用 QUIC 的数据报（Datagram）功能。以下是实现步骤：

### 步骤1：启用 Datagram 支持

首先，确保在服务器的连接设置中启用了 Datagram 支持。在 `src/server.c` 文件的 `xqc_mini_svr_init_args` 函数中，设置 `max_datagram_frame_size`：

```c
void
xqc_mini_svr_init_args(xqc_mini_svr_args_t *args)
{
    // ... 其他初始化代码 ...

    /* 启用 Datagram 支持 */
    args->quic_cfg.max_datagram_frame_size = 65535; // 设置为允许的最大数据报大小
}
```

### 步骤2：实现 Datagram 发送函数

在 `src/mini/mini_server_cb.c` 文件中，添加一个函数用于向指定客户端发送数据报：

```c
ssize_t
xqc_mini_svr_send_datagram(xqc_mini_svr_user_conn_t *user_conn, const unsigned char *data, size_t data_len)
{
    uint64_t dgram_id;
    xqc_data_qos_level_t qos_level = XQC_DATA_QOS_NORMAL; // 设置 QoS 等级，可根据需要调整

    ssize_t ret = xqc_datagram_send(user_conn->ctx->engine, &user_conn->cid, data, data_len, &dgram_id, qos_level);
    if (ret < 0) {
        printf("[error] xqc_datagram_send failed: %zd\n", ret);
    } else {
        printf("[info] Sent datagram with id: %lu to client.\n", dgram_id);
    }

    return ret;
}
```

### 步骤3：调用 Datagram 发送函数

在服务器需要发送数据的地方，调用上述 `xqc_mini_svr_send_datagram` 函数。例如，在处理某个事件或定时任务时：

```c
void some_event_handler(xqc_mini_svr_user_conn_t *user_conn)
{
    const unsigned char* message = (const unsigned char*)"Hello, client via Datagram!";
    size_t message_len = strlen((const char*)message);

    ssize_t sent = xqc_mini_svr_send_datagram(user_conn, message, message_len);
    if (sent < 0) {
        printf("[error] Failed to send datagram to client.\n");
    }
}
```

### 步骤4：配置 Transport Callbacks 处理 Datagram

在 `xqc_transport_callbacks_t` 结构体中，实现 `datagram_read_notify` 和其他相关回调，以处理数据报的接收和发送事件。例如：

```c
void
xqc_mini_svr_datagram_read_notify(const unsigned char *buf, size_t size, void *conn_user_data)
{
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)conn_user_data;
    printf("[info] Received datagram from client: %.*s\n", (int)size, buf);

    // 处理接收到的数据报
}
```

在初始化 transport callbacks 时，设置该回调函数：

```c
static xqc_transport_callbacks_t transport_cbs = {
    .server_accept = xqc_mini_svr_accept,
    .datagram_read_notify = xqc_mini_svr_datagram_read_notify,
    // 其他回调...
};
```

### 步骤5：确保 Datagram 回调被注册

在服务器初始化时，确保 transport callbacks 包含了 datagram 相关的回调：

```c
void
xqc_mini_svr_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *tcb,
    xqc_mini_svr_args_t *args)
{
    // ... 其他回调初始化代码 ...

    tcb->datagram_read_notify = xqc_mini_svr_datagram_read_notify;
    // 其他 datagram 回调（如需要）
}
```

---

## 注意事项

1. **连接上下文管理**：确保服务器能够正确维护和管理每个客户端的连接上下文（`xqc_mini_svr_user_conn_t`），以便在需要发送数据时，能够准确定位目标客户端。

2. **Datagram 支持限制**：虽然 Datagram 提供了主动发送数据的能力，但它在某些场景下可能不如流（Stream）稳定。请根据具体需求选择合适的传输方式。

3. **错误处理**：在发送数据时，务必检查返回值，处理可能的错误情况，确保服务器的健壮性。

4. **QoS 等级设置**：在发送数据报时，可以根据数据的重要性设置 QoS 等级（如 `XQC_DATA_QOS_NORMAL`），以优化数据传输的优先级和性能。

---

通过上述方法，您可以在服务器端实现向指定的客户端发送数据。根据具体的应用场景和需求，选择适合的传输方式（HTTP/3 响应或 Datagram）来进行数据通信。
