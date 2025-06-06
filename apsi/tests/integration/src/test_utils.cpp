#include "test_utils.h"
#include <algorithm>
#include <iomanip>
#include <numeric>
#include <random>
#include <stdexcept>
#include "gtest/gtest.h"

using namespace std;
using namespace apsi;
using namespace apsi::receiver;
using namespace apsi::util;
using namespace poseidon;

namespace APSITests
{
Label create_label(string &label_s)
{
    Label label;
    label.reserve(label_s.size());
    std::copy(label_s.begin(), label_s.end(), std::back_inserter(label));
    return label;
}

Label create_label(unsigned char start, size_t byte_count)
{
    Label label(byte_count);
    iota(label.begin(), label.end(), start);
    return label;
}

unordered_set<Item> rand_subset(const unordered_set<Item> &items, size_t size)
{
    mt19937_64 rg;

    set<size_t> ss;
    while (ss.size() != size)
    {
        ss.emplace(static_cast<size_t>(rg() % items.size()));
    }

    vector<Item> items_vec(items.begin(), items.end());
    unordered_set<Item> items_subset;
    for (auto idx : ss)
    {
        items_subset.insert(items_vec[idx]);
    }

    return items_subset;
}

unordered_set<Item> rand_subset(const unordered_map<Item, Label> &item_labels, size_t size)
{
    mt19937_64 rg;

    set<size_t> ss;
    while (ss.size() != size)
    {
        ss.emplace(static_cast<size_t>(rg() % item_labels.size()));
    }

    vector<Item> items_vec;
    transform(item_labels.begin(), item_labels.end(), back_inserter(items_vec),
              [](auto &il) { return il.first; });
    unordered_set<Item> items_subset;
    for (auto idx : ss)
    {
        items_subset.insert(items_vec[idx]);
    }

    return items_subset;
}

vector<Item> rand_subset(const vector<Item> &items, size_t size)
{
    mt19937_64 rg;

    set<size_t> ss;
    while (ss.size() != size)
    {
        ss.emplace(static_cast<size_t>(rg() % items.size()));
    }

    vector<Item> items_subset;
    for (auto idx : ss)
    {
        items_subset.push_back(items[idx]);
    }

    return items_subset;
}

vector<Item> rand_subset(const vector<pair<Item, Label>> &items, size_t size)
{
    mt19937_64 rg;

    set<size_t> ss;
    while (ss.size() != size)
    {
        ss.emplace(static_cast<size_t>(rg() % items.size()));
    }

    vector<Item> items_subset;
    for (auto idx : ss)
    {
        items_subset.push_back(items[idx].first);
    }

    return items_subset;
}

void verify_unlabeled_results(const vector<MatchRecord> &query_result,
                              const vector<Item> &query_vec, const vector<Item> &int_items)
{
    // Count matches
    size_t match_count = accumulate(query_result.cbegin(), query_result.cend(), size_t(0),
                                    [](auto sum, auto &curr) { return sum + curr.found; });

    // Check that intersection size is correct
    ASSERT_EQ(int_items.size(), match_count);

    // Check that every intersection item was actually found
    for (auto &item : int_items)
    {
        auto where = find(query_vec.begin(), query_vec.end(), item);
        ASSERT_NE(query_vec.end(), where);

        size_t idx = static_cast<size_t>(distance(query_vec.begin(), where));
        ASSERT_TRUE(query_result[idx].found);
    }
}

void verify_labeled_results(const vector<MatchRecord> &query_result, const vector<Item> &query_vec,
                            const vector<Item> &int_items,
                            const vector<pair<Item, Label>> &all_item_labels)
{
    verify_unlabeled_results(query_result, query_vec, int_items);

    // Verify that all labels were received for items that were found
    for (auto &result : query_result)
    {
        if (result.found)
        {
            ASSERT_TRUE(result.label);
        }
    }

    // Check that the labels are correct for items in the intersection
    for (auto &item : int_items)
    {
        auto where = find(query_vec.begin(), query_vec.end(), item);
        size_t idx = static_cast<size_t>(distance(query_vec.begin(), where));

        auto reference_label =
            find_if(all_item_labels.begin(), all_item_labels.end(),
                    [&item](auto &item_label) { return item == item_label.first; });
        ASSERT_NE(all_item_labels.end(), reference_label);

        size_t label_byte_count = reference_label->second.size();
        ASSERT_EQ(label_byte_count, query_result[idx].label.get_as<unsigned char>().size());

        ASSERT_TRUE(equal(reference_label->second.begin(), reference_label->second.end(),
                          query_result[idx].label.get_as<unsigned char>().begin()));
    }
}

PSIParams create_params1()
{
    PSIParams::ItemParams item_params;
    item_params.felts_per_item = 8;

    PSIParams::TableParams table_params;
    table_params.hash_func_count = 3;
    table_params.max_items_per_bin = 16;
    table_params.table_size = 4096;

    PSIParams::QueryParams query_params;
    query_params.query_powers = {1, 3, 5};

    PSIParams::PoseidonParams poseidon_params(8192);
    // poseidon_params.set_poly_modulus_degree(8192);
    // poseidon_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    poseidon_params.set_plain_modulus(65537);

    return {item_params, table_params, query_params, poseidon_params};
}

PSIParams create_params2()
{
    PSIParams::ItemParams item_params;
    item_params.felts_per_item = 7;

    PSIParams::TableParams table_params;
    table_params.hash_func_count = 3;
    table_params.max_items_per_bin = 16;
    table_params.table_size = 4680;

    PSIParams::QueryParams query_params;
    query_params.query_powers = {1, 3, 5};

    PSIParams::PoseidonParams poseidon_params(8192);
    // poseidon_params.set_poly_modulus_degree(8192);
    // poseidon_params.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    poseidon_params.set_plain_modulus(65537);

    return {item_params, table_params, query_params, poseidon_params};
}

PSIParams create_huge_params1()
{
    PSIParams::ItemParams item_params;
    item_params.felts_per_item = 8;

    PSIParams::TableParams table_params;
    table_params.hash_func_count = 4;
    table_params.max_items_per_bin = 70;
    table_params.table_size = 65536;

    PSIParams::QueryParams query_params;
    query_params.query_powers = {1, 3, 11, 15, 32};

    PSIParams::PoseidonParams poseidon_params(16384);
    // poseidon_params.set_poly_modulus_degree(16384);
    // poseidon_params.set_coeff_modulus(CoeffModulus::BFVDefault(16384));
    poseidon_params.set_plain_modulus(65537);

    return {item_params, table_params, query_params, poseidon_params};
}

PSIParams create_huge_params2()
{
    PSIParams::ItemParams item_params;
    item_params.felts_per_item = 7;

    PSIParams::TableParams table_params;
    table_params.hash_func_count = 4;
    table_params.max_items_per_bin = 70;
    table_params.table_size = 74880;

    PSIParams::QueryParams query_params;
    query_params.query_powers = {1, 3, 11, 15, 32};

    PSIParams::PoseidonParams poseidon_params(16384);
    // poseidon_params.set_poly_modulus_degree(16384);
    // poseidon_params.set_coeff_modulus(CoeffModulus::BFVDefault(16384));
    poseidon_params.set_plain_modulus(65537);

    return {item_params, table_params, query_params, poseidon_params};
}

void choice()
{
    std::cout << "请选择软件或者硬件 s/h : " << std::endl;
    while (true)
    {
        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "s")
        {
            poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);
            std::cout << "接下来的查询用软件进行！" << std::endl;
            return;
        }
        else if (choice == "h")
        {
            std::cout << "接下来的查询用硬件进行！" << std::endl;
            poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_HARDWARE);
            return;
        }
        else
        {
            std::cout << "输入错误，请重新输入！ 软件(s)/硬件(h)" << std::endl;
        }
    }
}

vector<apsi::Item> get_item()
{
    // choice();
    vector<apsi::Item> recv_items;
    std::cout << "请输入航运ID，支持多个ID，以回车为区分（输入ok结束）: " << std::endl;
    int i = 1;
    while (true)
    {
        cout << "请输入第" << i << "个ID，或(ok结束): ";
        std::string input;
        std::array<unsigned char, 16> arr{};

        // 读取单行输入
        std::getline(std::cin, input);

        if (input == "ok")
        {
            std::cout << "一共输入" << i - 1 << "个ID，开始查询." << std::endl;
            return recv_items;
        }

        // 验证长度
        if (input.size() != 16)
        {
            std::cout << "输入格式错误，请重新输入或者结束输入(输入ok结束)" << std::endl;
            continue;
        }

        // 将数据存入array
        std::copy(input.begin(), input.end(), arr.begin());
        recv_items.push_back({arr});
        i++;
    }
}

vector<pair<apsi::Item, apsi::Label>> init_server_data(const std::string filename)
{
    vector<pair<apsi::Item, apsi::Label>> sender_items;
    ifstream file(filename);
    if (!file.is_open())
    {
        throw runtime_error("无法打开文件: " + filename);
    }
    std::string line;
    while (getline(file, line))
    {
        stringstream line_stream(line);
        string prefix_str, suffix_str;

        // 按逗号分割字符串
        if (!getline(line_stream, prefix_str, ',') || !getline(line_stream, suffix_str))
        {
            cerr << "格式错误，跳过行: " << line << endl;
            continue;
        }

        // 检查前16位长度
        if (prefix_str.size() != 16)
        {
            cerr << "前导字符长度不足16位，跳过行: " << line << endl;
            continue;
        }
        std::array<unsigned char, 16> arr;
        std::copy(prefix_str.begin(), prefix_str.end(), arr.begin());
        // 填充数据结构
        sender_items.push_back(make_pair(apsi::Item(arr), create_label(suffix_str)));
    }
    file.close();
    return sender_items;
}

void print_progress(int distance, const string &name)
{
    for (int progress = 0; progress <= 100; ++progress)
    {
        float percent = 100.0 * progress / 100;
        std::cout << " " << name << ": [";
        int pos = 50 * progress / 100;
        for (int i = 0; i < 50; ++i)
            std::cout << (i <= pos ? '=' : ' ');
        std::cout << "] " << int(percent) << "%\r";
        std::cout.flush();
        usleep(distance);
    }
    std::cout << std::endl;
}

char rand_ew()
{
    int rand = std::rand() % 2;
    if (rand)
        return 'E';
    return 'W';
}

char rand_sn()
{
    int rand = std::rand() % 2;
    if (rand)
        return 'N';
    return 'S';
}

void hangyun(int size)
{
    for (int i = 0; i < size; ++i)
    {
        double weidu = (std::rand() % 90000) / 1000.0;
        int weidu_int = static_cast<int>(weidu);
        double weidu_float = weidu - weidu_int;
        double jingdu = (std::rand() % 180000) / 1000.0;
        int jingdu_int = static_cast<int>(jingdu);
        double jingdu_float = jingdu - jingdu_int;
        std::cout << std::setw(16) << std::setfill('0') << i << "," << std::setw(3)
                  << std::setfill('0') << jingdu_int << "." << std::setw(3) << std::setfill('0')
                  << static_cast<int>(jingdu_float * 1000) << rand_ew() << " " << std::setw(2)
                  << std::setfill('0') << weidu_int << "." << std::setw(3) << std::setfill('0')
                  << static_cast<int>(weidu_float * 1000) << rand_sn() << std::endl;
    }
}

void hangyun2(int size)
{
    for (int i = 0; i < size; ++i)
    {
        double weidu = (std::rand() % 90000) / 1000.0;
        double jingdu = (std::rand() % 180000) / 1000.0;
        std::cout << std::setw(16) << std::setfill('0') << i << "," << jingdu << rand_ew() << " "
                  << weidu << rand_sn() << std::endl;
    }
}

}  // namespace APSITests
