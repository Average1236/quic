// quic.cpp
#include "quic.h"

QUICManager::QUICManager(Mode mode) : mode_(mode) 
{
    memset(&cli_ctx_, 0, sizeof(cli_ctx_));
    memset(&svr_ctx_, 0, sizeof(svr_ctx_));
}


QUICManager::~QUICManager() 
{
    cleanup();
}

int QUICManager::init() 
{
    if (mode_ == Mode::CLIENT) {
        return init_client();
    }
    return init_server();
}

void QUICManager::run() 
{
    struct event_base* eb = get_event_base();
    if (eb) {
        event_base_dispatch(eb);
    }
}


// Client context
xqc_mini_cli_ctx_t cli_ctx_;
xqc_mini_cli_args_t* cli_args_ = nullptr;
xqc_mini_cli_user_conn_t* cli_conn_ = nullptr;

// Server context
xqc_mini_svr_ctx_t svr_ctx_;
xqc_mini_svr_args_t* svr_args_ = nullptr;
xqc_mini_svr_user_conn_t* svr_conn_ = nullptr;

struct event_base* QUICManager::get_event_base() {
    return (mode_ == Mode::CLIENT) ? cli_ctx_.eb : svr_ctx_.eb;
}

int QUICManager::init_client() {
    cli_args_ = static_cast<xqc_mini_cli_args_t*>(calloc(1, sizeof(xqc_mini_cli_args_t)));
    if (!cli_args_) return -1;

    if (xqc_mini_cli_init_env(&cli_ctx_, cli_args_) < 0) return -1;
    if (xqc_mini_cli_init_xquic_engine(&cli_ctx_, cli_args_) < 0) return -1;
    if (xqc_mini_cli_init_engine_ctx(&cli_ctx_) < 0) return -1;

    cli_conn_ = xqc_mini_cli_user_conn_create(&cli_ctx_);
    if (!cli_conn_) return -1;

    // xqc_mini_cli_main_process(cli_conn_, &cli_ctx_);
    return 0;
}

int QUICManager::init_server() {
    svr_args_ = static_cast<xqc_mini_svr_args_t*>(calloc(1, sizeof(xqc_mini_svr_args_t)));
    if (!svr_args_) return -1;

    if (xqc_mini_svr_init_env(&svr_ctx_, svr_args_) < 0) return -1;
    if (xqc_mini_svr_init_xquic_engine(&svr_ctx_, svr_args_) < 0) return -1;
    if (xqc_mini_svr_init_engine_ctx(&svr_ctx_, svr_args_) < 0) return -1;

    svr_conn_ = xqc_mini_svr_create_user_conn(&svr_ctx_);
    return svr_conn_ ? 0 : -1;
}

void QUICManager::cleanup() {
    if (mode_ == Mode::CLIENT) {
        if (cli_ctx_.engine) xqc_engine_destroy(cli_ctx_.engine);
        if (cli_conn_) {
            xqc_mini_cli_on_connection_finish(cli_conn_);
            xqc_mini_cli_free_user_conn(cli_conn_);
        }
        xqc_mini_cli_free_ctx(&cli_ctx_);
    } else {
        if (svr_ctx_.engine) xqc_engine_destroy(svr_ctx_.engine);
        if (svr_conn_) xqc_mini_svr_free_user_conn(svr_conn_);
        xqc_mini_svr_free_ctx(&svr_ctx_);
    }
}

int QUICManager::connect(const std::string& server_addr, uint16_t port) {
    if (mode_ != Mode::CLIENT) return -1;

    // 更新服务器地址
    if (!server_addr.empty() && port != 0) {
        set_server_address(server_addr, port);
    }

    // 触发主处理流程
    xqc_mini_cli_main_process(cli_conn_, &cli_ctx_);
    return 0;
}

bool validate_ip_address(const std::string& addr) {
    struct sockaddr_in sa;
    // 尝试解析为 IPv4 地址
    if (inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) == 1) {
        return true;
    }
    
    struct sockaddr_in6 sa6;
    // 尝试解析为 IPv6 地址
    return inet_pton(AF_INET6, addr.c_str(), &sa6.sin6_addr) == 1;
}

void QUICManager::set_server_address(const std::string& addr, uint16_t port) {
    if (mode_ != Mode::CLIENT) return;

    // 参数有效性检查
    if (addr.empty()) {
        cached_addr_ = DEFAULT_HOST;
    } else {
        // 验证IP地址格式
        if (!validate_ip_address(addr)) {
            throw std::invalid_argument("Invalid IP address format");
        }
        cached_addr_ = addr;
    }
    
    // 端口范围检查
    cached_port_ = (port > 0 && port <= 65535) ? port : DEFAULT_PORT;

    if (cli_conn_) {
        xqc_mini_cli_convert_text_to_sockaddr(
            AF_INET, cached_addr_.c_str(), cached_port_,
            &(cli_conn_->peer_addr), &(cli_conn_->peer_addrlen));
    }
    else {
        printf("cli_conn_ is nullptr\n");
    }

    // 触发回调通知
    if (addr_callback_) {
        addr_callback_(cached_addr_, cached_port_);
    }
}


// 使用示例
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <client|server>\n", argv[0]);
        return -1;
    }

    QUICManager::Mode mode = (strcmp(argv[1], "client") == 0) ?
        QUICManager::Mode::CLIENT : QUICManager::Mode::SERVER;

    if (mode == QUICManager::Mode::SERVER) {
        // 初始化服务器
        QUICManager server(QUICManager::Mode::SERVER);
        if (server.init() != 0) {
            printf("Initialize failed\n");
            return -1;
        }
        server.run();
    } else {
        // 初始化客户端
        QUICManager client(QUICManager::Mode::CLIENT);
        
        // 初始化基础环境
        if (client.init() != 0) {
            printf("Initialize failed\n");
            return -1;
        }

        // 设置地址获取回调
        client.set_address_ready_callback([](const std::string& addr, uint16_t port) {
            printf("Connecting to: %s:%d\n", addr.c_str(), port);
        });

        // 动态获取服务器地址（示例）
        std::string server_addr = DEFAULT_IP; // 自定义地址发现逻辑
        uint16_t port = DEFAULT_PORT;           // 端口发现逻辑
        
        // 建立连接
        if (client.connect(server_addr, port) != 0) {
            printf("Connection failed\n");
            return -1;
        }

        // 运行事件循环
        client.run();
    }
    return 0;
}