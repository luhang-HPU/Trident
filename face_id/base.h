#pragma once

#include "poseidon/src/plaintext.h"
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <chrono>

namespace facial_recognition {
    using FEATURE_VECTOR = std::vector<double>;
    using FEATURE_DATABASE = std::map<std::string, poseidon::Plaintext>;

    static bool read_vector(const std::string& file, FEATURE_VECTOR& vec) {
        std::ifstream ifs(file);
        if (!ifs.is_open()) {
            std::cout << "file error" << std::endl;
            return false;
        }

        vec.resize(1024);
        for (auto i = 0; ifs >> vec[i] && i < 1024; ++i) {}
        return true;
    }

    static int get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return (int)std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    }
}
