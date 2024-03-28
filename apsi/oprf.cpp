#include <array>

// APSI

#include "kuku/kuku.h"
#include "poseidon/Release/define.h"
#include "gsl/span"
#include "ecpoint.h"
#include "item.h"

#include "oprf.h"

using namespace kuku;


using namespace std;
using namespace poseidon;   
using namespace oprf;  

void print_table(const KukuTable &table)
{
    table_size_type col_count = 8;
    for (table_size_type i = 0; i < table.table_size(); i++)
    {
        const auto &item = table.table(i);
        cout << setw(5)
            << i << ": " << setw(5) << get_high_word(item) << "," << get_low_word(item)
            << ((i % col_count == col_count - 1) ? "\n" : "\t");
    }

    cout << endl << endl << "Stash: " << endl;
    for (table_size_type i = 0; i < table.stash().size(); i++)
    {
        const auto &item = table.stash(i);
        cout << i << ": " << get_high_word(item) << "," << get_low_word(item) << endl;
    }
    cout << endl;

}

void process_items(gsl::span<Item> oprf_items)
{


    auto oprf_out_ptr = oprf_queries_.begin();
    

    

    for (size_t i = 0; i < 2; i++) {
        // 从输入项oprf_items[i]创建一个椭圆曲线点
        ECPoint ecpt(oprf_items[i].get_as<const unsigned char>());
        // 创建一个随机标量用于OPRF，并保存其逆
        ECPoint::scalar_type random_scalar;
        // 生成一个非零随机标量
        ECPoint::MakeRandomNonzeroScalar(random_scalar);
        // 计算并保存random_scalar的逆
        ECPoint::InvertScalar(random_scalar, inv_factor_data_.get_factor(i));
        // 使用生成的随机标量乘以椭圆曲线点
        ecpt.scalar_multiply(random_scalar, false);
        // 将结果保存到items_buffer（通过oprf_out_ptr指针）
        ecpt.save(ECPoint::point_save_span_type{ oprf_out_ptr, oprf_query_size });
        // 移动oprf_out_ptr指针到下一个位置
        advance(oprf_out_ptr, oprf_query_size);

    }
    printf("item process!!!\n");
//    for (std::size_t i = 0; i < 2; ++i) {
//    auto factor = inv_factor_data_.get_factor(i);
//    // 打印每个因子
//    for (auto byte : factor) {
//        std::printf("%02x ", byte); // 以十六进制格式打印
//    }
//    std::printf("\n"); // 每个因子打印完毕后换行
//}
}



namespace oprf {
    bool OPRFKey::operator==(const OPRFKey &compare) const
    {
        return compare_bytes(oprf_key_.cbegin(), compare.oprf_key_.cbegin(), oprf_key_size);
    }
    void OPRFKey::save(oprf_key_span_type oprf_key) const
    {
        copy_n(oprf_key_.cbegin(), oprf_key_size, oprf_key.data());
    }
    void OPRFKey::load(oprf_key_span_const_type oprf_key)
    {
        copy_n(oprf_key.data(), oprf_key_size, oprf_key_.begin());
    }
    void OPRFKey::save(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        stream.exceptions(ios_base::badbit | ios_base::failbit);
        try {
            stream.write(reinterpret_cast<const char *>(oprf_key_.cbegin()), oprf_key_size);
        } catch (const ios_base::failure &) {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        stream.exceptions(old_except_mask);
    }
    void OPRFKey::load(istream &stream)
    {
        auto old_except_mask = stream.exceptions();
        stream.exceptions(ios_base::badbit | ios_base::failbit);
        try {
            stream.read(reinterpret_cast<char *>(oprf_key_.begin()), oprf_key_size);
        } catch (const ios_base::failure &) {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        stream.exceptions(old_except_mask);
    }
    
    bool compare_bytes(const void *first, const void *second, std::size_t count)
    {
        auto first_begin = reinterpret_cast<const unsigned char *>(first);
        auto first_end = first_begin + count;
        auto second_begin = reinterpret_cast<const unsigned char *>(second);
        return equal(first_begin, first_end, second_begin);
    }
}

vector<unsigned char> ProcessQueries(
    gsl::span<const unsigned char> oprf_queries, const OPRFKey &oprf_key)
{
    // 计算查询的数量
    size_t query_count = 2;
    //int n=query_count;
   // printf("%d",n);
    // 为响应创建缓冲区
    vector<unsigned char> oprf_responses(2 * oprf_response_size);

    // 定义指向输入查询和输出响应的指针
    auto oprf_in_ptr = oprf_queries.data();
    auto oprf_out_ptr = oprf_responses.data();

    // 对于每个查询
    for (size_t idx = 0; idx < query_count; idx++) {
        // 从输入缓冲区加载点
        ECPoint ecpt;

        ecpt.load(ECPoint::point_save_span_const_type{oprf_in_ptr , oprf_query_size });

        // 使用密钥进行标量乘法
        if (!ecpt.scalar_multiply(oprf_key.key_span(), true)) {
            throw logic_error("scalar multiplication failed due to invalid query data");
        }
        
        // 将结果保存到oprf_responses
        ecpt.save(ECPoint::point_save_span_type{oprf_out_ptr , oprf_response_size });
        advance(oprf_in_ptr, oprf_query_size);
        advance(oprf_out_ptr, oprf_response_size);
    }
    printf("queries process!!!\n");

    // 返回响应
    return oprf_responses;
}



void process_responses(
    gsl::span<const unsigned char> oprf_responses,
    gsl::span<HashedItem> oprf_hashes) 
{
    vector<unsigned char> test_responses(2 * oprf_response_size);
    auto oprf_in_ptr = oprf_responses.data();
    auto oprf_out_ptr = test_responses.data();
    
    
    // 遍历每个响应项
    for (size_t i = 0; i < 2; i++) {
        // 从oprf_in_ptr指向的数据加载一个ECPoint对象
        ECPoint ecpt;
        ecpt.load(ECPoint::point_save_span_const_type{ oprf_in_ptr, oprf_response_size });

        // 使用inv_factor_data_.get_factor(i)获取的逆随机标量与ecpt相乘
        ecpt.scalar_multiply(inv_factor_data_.get_factor(i), false);

        // 将oprf_in_ptr指针前进oprf_response_size个字节，以便处理下一个响应项
        ecpt.save(ECPoint::point_save_span_type{oprf_out_ptr , oprf_response_size });

        // 将item_hash的前oprf_hash_size字节复制到oprf_hashes[i].value().data()
        copy_n(oprf_out_ptr, 16, oprf_hashes[i].value().data());

        advance(oprf_in_ptr, oprf_response_size);
        advance(oprf_out_ptr, oprf_response_size);
 
       
    }
    
        for (const auto& item : oprf_hashes) {
        const auto& value = item.value(); // 获取 value 数组

       //  以十进制格式打印数组的每个字节
        for (unsigned char byte : value) {
            std::cout << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
     printf("process_responses!!!\n");
     

}


vector<unsigned char> process_db(
    gsl::span<Item> db, const OPRFKey &oprf_key)
{
    // 计算查询的数量
    size_t db_count = 5;
    // 为响应创建缓冲区
    vector<unsigned char> db_responses(5 * oprf_response_size);

    // 定义指向输入查询和输出响应的指针

    auto oprf_out_ptr = db_responses.data();

    // 对于每个查询
    for (size_t idx = 0; idx < 5; idx++) {
        // 从输入缓冲区加载点
        ECPoint ecpt(db[idx].get_as<const unsigned char>());

        // 使用密钥进行标量乘法
        if (!ecpt.scalar_multiply(oprf_key.key_span(), true)) {
            throw logic_error("scalar multiplication failed due to invalid query data");
        }
        
        // 将结果保存到oprf_responses     
        ecpt.save(ECPoint::point_save_span_type{oprf_out_ptr , oprf_response_size });
        
        advance(oprf_out_ptr, oprf_response_size);
    }
    for (unsigned char byte : db_responses) {
        // 直接打印每个字节的十进制值
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
    return db_responses;
    

}

void create_query(const vector<HashedItem> &items)
{
    IndexTranslationTable itt;
    itt.item_count_ = items.size();

    // 创建布谷鸟哈希表
    KukuTable cuckoo(
        10,      // 哈希表大小
        0,                                      // 不使用stash
        3, // 哈希函数数量
        { 0, 0 },                               // 用硬编码的 { 0, 0 } 作为哈希函数的种子
        500,           // 定义 Cuckoo 哈希表插入操作的尝试次数
        { 0, 0 });                              // 定义空元素的值


    {
       for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
            const auto &item = items[item_idx];
            if (!cuckoo.insert(item.get_as<kuku::item_type>().front())) {
                //Cuckoo 哈希表的过程中可能遇到的两种失败情况：
                //如果要插入的项已经在哈希表中，插入操作将不会进行，并且返回的 "leftover item"（剩余项）为空。
              if (cuckoo.is_empty_item(cuckoo.leftover_item())) {
                    throw invalid_argument("Skipping repeated insertion of items");
                }
            }
        }

    }
   print_table(cuckoo);
   
    // 填充表格后，填充table_idx_to_item_idx映射
    for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
        auto item_loc = cuckoo.query(items[item_idx].get_as<kuku::item_type>().front());
        itt.table_idx_to_item_idx_[item_loc.location()] = item_idx;
        printf("%d",item_loc.location());
    }
    printf("create query!!!");
    for (uint32_t bundle_idx = 0; bundle_idx < 16;
                     bundle_idx++) {

                    // 首先，查找此bundle index的项目
                    gsl::span<const item_type> bundle_items(
                        cuckoo.table().data() + bundle_idx * 16,
                        16);

                    vector<uint64_t> alg_items;
                    for (auto &item : bundle_items) {
                        // 现在为该项目设置BitstringView
                        gsl::span<const unsigned char> item_bytes(
                            reinterpret_cast<const unsigned char *>(item.data()), sizeof(item));
                        BitstringView<const unsigned char> item_bits(
                            item_bytes, 16);

                        // 通过将项分解为明文模数的部分来创建代数项

                    }
     }

}

void process_dbresponses(
    gsl::span<const unsigned char> oprf_responses,
    gsl::span<HashedItem> oprf_hashes) 
{
    vector<unsigned char> tes_responses(5 * oprf_response_size);
    auto oprf_in_ptr = oprf_responses.data();
    auto oprf_out_ptr = tes_responses.data();
    
    
    // 遍历每个响应项
    for (size_t i = 0; i < 5; i++) {
        // 从oprf_in_ptr指向的数据加载一个ECPoint对象
        ECPoint ecpt;
        ecpt.load(ECPoint::point_save_span_const_type{ oprf_in_ptr, oprf_response_size });

        // 将oprf_in_ptr指针前进oprf_response_size个字节，以便处理下一个响应项
        ecpt.save(ECPoint::point_save_span_type{oprf_out_ptr , oprf_response_size });

        // 将item_hash的前oprf_hash_size字节复制到oprf_hashes[i].value().data()
        copy_n(oprf_out_ptr, 16, oprf_hashes[i].value().data());

        advance(oprf_in_ptr, oprf_response_size);
        advance(oprf_out_ptr, oprf_response_size);
 
       
    }
    
    for (const auto& item : oprf_hashes) {

        const auto& value = item.value(); // 获取 value 数组

       //  以十进制格式打印数组的每个字节
        for (unsigned char byte : value) {
            std::cout << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
    
     printf("process_dbresponses!!!\n");
     

}



