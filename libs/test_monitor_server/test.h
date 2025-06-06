#pragma once

#include "../cinatra/cinatra.hpp"
#include "../nlohmann_json/json.hpp"

namespace facial_recognition
{

class Server
{
public:
    static Server &getInstance();
    void run();

};
}
