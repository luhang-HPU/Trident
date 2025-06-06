#include "test.h"

namespace facial_recognition
{
Server &Server::getInstance()
{
    static Server instance;
    return instance;
}

void Server::run()
{

    int max_thread_num = 4;
    cinatra::http_server server(max_thread_num);
    server.listen("0.0.0.0", "8088");
    std::cout << "backend server start" << std::endl;

    // test
    server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>(
        "/",
        [&](cinatra::request &req, cinatra::response &res)
        {
            res.set_status_and_content(cinatra::status_type::ok, nlohmann::json{"backend server alive"}.dump());
        });

    // monitor
    server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>(
        "/getCompute",
        [&](cinatra::request &req, cinatra::response &res)
        {
            std::cout << "getCompute start:" << std::endl;
            auto data = req.body();
            std::cout << data << std::endl;
            auto json = nlohmann::json::parse(data);
            res.set_status_and_content(cinatra::status_type::ok,
                                       nlohmann::json{"ok"}.dump());
        });

    server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>(
        "/getCpuMemory",
        [&](cinatra::request &req, cinatra::response &res)
        {
            std::cout << "getCpuMemory start:" << std::endl;
            auto data = req.body();
            std::cout << data << std::endl;
            auto json = nlohmann::json::parse(data);
            res.set_status_and_content(cinatra::status_type::ok, nlohmann::json{"ok"}.dump());
        });

    server.run();
}

}

int main()
{
    facial_recognition::Server::getInstance().run();
    return 0;
}