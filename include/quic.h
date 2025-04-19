// quic.h
#pragma once
#include <string>
#include <functional>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <arpa/inet.h>
#include <stdexcept>
#include "client.h"
#include "server.h"

class QUICManager {
public:
    enum class Mode { CLIENT, SERVER };
    using AddressCallback = std::function<void(const std::string&, uint16_t)>;

    explicit QUICManager(Mode mode);
    ~QUICManager();

    int init();
    int connect(const std::string& server_addr = "", uint16_t port = 0);
    void set_server_address(const std::string& addr, uint16_t port);
    void run();

    // 服务器地址获取完成回调接口
    void set_address_ready_callback(AddressCallback cb) { addr_callback_ = cb; }

private:
    Mode mode_;
    
    // Client context
    xqc_mini_cli_ctx_t cli_ctx_;
    xqc_mini_cli_args_t* cli_args_ = nullptr;
    xqc_mini_cli_user_conn_t* cli_conn_ = nullptr;

    // Server context
    xqc_mini_svr_ctx_t svr_ctx_;
    xqc_mini_svr_args_t* svr_args_ = nullptr;
    xqc_mini_svr_user_conn_t* svr_conn_ = nullptr;

    struct event_base* get_event_base();

    int init_client();
    int init_server();
    void cleanup();

    std::string cached_addr_;
    uint16_t cached_port_ = 0;
    AddressCallback addr_callback_;
};

bool validate_ip_address(const std::string& addr);