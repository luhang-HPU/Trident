#pragma once

#include "../nlohmann_json/json.hpp"
#include <sstream>

enum ERROR_TYPE {
    DEFAULT = 0,
    OK = 1,
    JSON_DATA_TYPE_ERROR = 2,
    JSON_CODE_ERROR = 3,
};


nlohmann::json stream_to_json(std::stringstream& ss);

std::stringstream json_to_stream(nlohmann::json& json);

/*
 * parse json to get the data
 * json format
 * {
 *     "code": int,
 *     "message": string,
 *     "timestamp": int,
 *     "data": {...}      <---------------------------------|
 * }                                                        |
 *                                                          |
 * @return bool: return true if parse json success          |
 * @param json: json received                               |
 * @param data: "data"  in json received  ------------------|
 * @param code: "code" in json received
 * @param message: "message" in json received
 * @param error_message: if parse json failed, output the error message
 */
//bool parse_json(nlohmann::json& json, nlohmann::json& data, int& code, std::string& message, std::string& error_message);
nlohmann::json generate_json(int code, std::string& message, int timestamp, nlohmann::json& data);
nlohmann::json generate_json(int code, std::string&& message, int timestamp, nlohmann::json&& data);

///*
// * @return bool: return true if get json code success
// */
//[[nodiscard]] bool get_json_code(nlohmann::json& json, int& code);
//void set_json_code(nlohmann::json& json, int code);
//
///*
// * @return bool: return true if get json message success
// */
//[[nodiscard]] bool get_json_message(nlohmann::json& json, std::string& message);
//void set_json_message(nlohmann::json& json, std::string& message);
//
///*
// * @return bool: return true if get json timestamp success
// */
//[[nodiscard]] bool get_json_timestamp(nlohmann::json& json, int& timestamp);
//void set_json_timestamp(nlohmann::json& json, int timestamp);
//
///*
// * @return bool: return true if get json data success
// */
//[[nodiscard]] bool get_json_data(nlohmann::json& json, nlohmann::json& data);
//void set_json_data(nlohmann::json& json, nlohmann::json& data);
