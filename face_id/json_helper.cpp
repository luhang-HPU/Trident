#include "json_helper.h"

nlohmann::json stream_to_json(std::stringstream& ss) {
    std::vector<uint8_t> vec_byte;
    char c;
    while (ss.get(c)) {
        vec_byte.push_back(c);
    }
    return nlohmann::json::binary(vec_byte, 0);
}

std::stringstream json_to_stream(nlohmann::json& json) {
    if (!json.is_array()) {
        throw "json_to_stream error";
    }

    std::stringstream ss(std::ios_base::binary | std::ios_base::in | std::ios_base::out);
    for (auto iter = json.cbegin(); iter != json.cend(); ++iter) {
        uint8_t x = *iter;
        ss << x;
    }
    return ss;
}

//bool parse_json(nlohmann::json& json, nlohmann::json& data, int& code, std::string& message, std::string& error_message) {
//    if (!get_json_code(json, code)) {
//        error_message = "get code fail";
//        return false;
//    }
//
//    if (code < 0) {
//        if (!get_json_message(json, message)) {
//            error_message = "code < 0 and get message fail";
//            return false;
//        }
//    }
//
//    // ignore "timestamp"
////    if (!get_json_timestamp(json, timestamp)) {
////
////    }
//
//    if (!get_json_data(json, data)) {
//        error_message = "get data fail";
//        return false;
//    }
//
//    return true;
//}

nlohmann::json generate_json(int code, std::string& message, int timestamp, nlohmann::json& data) {
    nlohmann::json json;

    json["code"] = code;
    json["message"] = message;
    json["timestamp"] = timestamp;
    json["data"] = data;

    return json;
}

nlohmann::json generate_json(int code, std::string&& message, int timestamp, nlohmann::json&& data) {
    nlohmann::json json;

    json["code"] = code;
    json["message"] = message;
    json["timestamp"] = timestamp;
    json["data"] = data;

    return json;
}

//bool get_json_code(nlohmann::json& json, int& code) {
//    auto code_json = json["code"];
//    if (!code_json.is_number_integer()) {
//        return false;
//    }
//
//    code = code_json;
//    if (code < 0) {
//        return false;
//    }
//
//    return true;
//}
//
//bool get_json_message(nlohmann::json& json, std::string& message) {
//    auto message_json = json[message];
//    if (!message_json.is_string()) {
//        return false;
//    }
//
//    message = message_json;
//    return true;
//}
//
//bool get_json_timestamp(nlohmann::json& json, int& timestamp) {
//    auto timestamp_json = json[timestamp];
//    if (!timestamp_json.is_number_integer()) {
//        return false;
//    }
//
//    timestamp = timestamp_json;
//    return true;
//}
//
//bool get_json_data(nlohmann::json& json, nlohmann::json& data) {
//    auto data_json = json[data];
////    if (!data_json.is_object()) {
////        return false;
////    }
//    data = data_json;
//    return true;
//}

