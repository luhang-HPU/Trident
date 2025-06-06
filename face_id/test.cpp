#include "test.h"

namespace facial_recognition {
    void test_main() {
//    facial_recognition::FrontendServer frontend_server;
//    facial_recognition::BackendServer backend_server;
//
//    facial_recognition::FEATURE_VECTOR feat_vec(1024);
//    facial_recognition::read_vector("/home/tangjiajian/Desktop/face_id/data2.txt", feat_vec);
//
//    nlohmann::json key_json = frontend_server.handler_galois_key();
//    nlohmann::json ciphertext_json = frontend_server.handler_feature_vector(feat_vec);
//
//    backend_server.handle_set_galois_key(key_json);
//    nlohmann::json ret_json = backend_server.handler_get_id(ciphertext_json);
//
//    std::string max_id = frontend_server.handler_get_id(ret_json);
//
//    if (max_id.empty()) {
//        std::cout << "no match" << std::endl;
//        return -1;
//    }
//    std::cout << max_id << std::endl;
    }


    // to serialize the parameterLiateral, the GaloisKeys and the ciphertext
//void hardware_single_test() {
//    ParametersLiteralDefault parm(CKKS,4096,poseidon::sec_level_type::none);
//    PoseidonContext context(parm, poseidon::sec_level_type::none, true);
//    double scale = pow(2.0, 32);
//
//    // input feature vector
//    std::string file1 = "/home/tangjiajian/Desktop/face_id/data1.txt";
//    std::string file2 = "/home/tangjiajian/Desktop/face_id/data2.txt";
//    std::string file3 = "/home/tangjiajian/Desktop/face_id/data3.txt";
//    poseidon::facial_recognition::FEATURE_VECTOR feat_vec_1(1024);
//    poseidon::facial_recognition::FEATURE_VECTOR feat_vec_2(1024);
//    poseidon::facial_recognition::read_vector(file1, feat_vec_1);
//    poseidon::facial_recognition::read_vector(file2, feat_vec_2);
//
//    // encode feature vector
//    poseidon::CKKSEncoder encoder(context);
//    Plaintext feat_vec_ptxt;
//    encoder.encode(feat_vec_1, scale, feat_vec_ptxt);
//    Plaintext ptxt;
//    encoder.encode(feat_vec_2, scale, ptxt);
//
//    poseidon::PublicKey public_key;
//    poseidon::RelinKeys relinKeys;
//    poseidon::GaloisKeys galoisKeys;
//
//    poseidon::KeyGenerator keygen(context);
//    keygen.create_public_key(public_key);
//    keygen.create_relin_keys(relinKeys);
//    keygen.create_galois_keys(std::vector<int>{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}, galoisKeys);
//
//    // encrypt feature vector into ciphertext
//    Ciphertext feat_vec_ctxt;
//    poseidon::Encryptor encryptor(context,public_key);
//    encryptor.encrypt(feat_vec_ptxt, feat_vec_ctxt);
//
//    // transfer the feature vector ciphertext
//    Ciphertext ctxt_temp;
//    poseidon::CKKSEvaluator_H evaluator(context);
//    evaluator.multiply_plain(feat_vec_ctxt, ptxt, ctxt_temp);
//    evaluator.rescale(ctxt_temp, ctxt_temp);
//    evaluator.drop_modulus_to_next(ctxt_temp, ctxt_temp);
//
//    // rotate
//    evaluator.read(ctxt_temp);
//    Ciphertext ctxt_result = ctxt_temp;
//    for (auto i = 1; i < 1024; i <<= 1) {
//        ctxt_temp = ctxt_result;
//        //poseidon::facial_recognition::clear_id(ctxt_temp);
//        evaluator.rotate(ctxt_temp, i, galoisKeys, ctxt_temp);
//        evaluator.add(ctxt_result, ctxt_temp, ctxt_result);
//        evaluator.read(ctxt_result);
//    }
//
//    // decrypt the result ciphertext
//    poseidon::Decryptor decryptor(context, keygen.secret_key());
//    Plaintext ptxt_tmp;
//    decryptor.decrypt(ctxt_result, ptxt_tmp);
//
//    std::vector<double> ans;
//    encoder.decode(ptxt_tmp, ans);
//
//    // output max id
//    std::cout << "result = " << ans[0] << std::endl;
//}

//void hardware_multi_test() {
//    ParametersLiteralDefault parm(CKKS,4096,poseidon::sec_level_type::none);
//    PoseidonContext context(parm, poseidon::sec_level_type::none, true);
//    double scale = pow(2.0, 32);
//
//    // input feature vector
//    std::string file1 = "/home/tangjiajian/Desktop/face_id/data1.txt";
//    std::string file2 = "/home/tangjiajian/Desktop/face_id/data2.txt";
//    std::string file3 = "/home/tangjiajian/Desktop/face_id/data3.txt";
//    poseidon::facial_recognition::FEATURE_VECTOR feat_vec(1024);
//    poseidon::facial_recognition::read_vector(file2, feat_vec);
//
//    // encode feature vector
//    poseidon::CKKSEncoder encoder(context);
//    Plaintext feat_vec_ptxt;
//    encoder.encode(feat_vec, scale, feat_vec_ptxt);
//
//    poseidon::PublicKey public_key;
//    poseidon::RelinKeys relinKeys;
//    poseidon::GaloisKeys galoisKeys;
//
//    poseidon::KeyGenerator keygen(context);
//    keygen.create_public_key(public_key);
//    keygen.create_relin_keys(relinKeys);
//    keygen.create_galois_keys(std::vector<int>{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}, galoisKeys);
//
//    // encrypt feature vector into ciphertext
//    Ciphertext feat_vec_ctxt;
//    poseidon::Encryptor encryptor(context,public_key);
//    encryptor.encrypt(feat_vec_ptxt, feat_vec_ctxt);
//
//    // transfer the feature vector ciphertext
//    poseidon::facial_recognition::Server processer(poseidon::sec_level_type::none);
//    auto result = processer.compute(feat_vec_ctxt);
//
//    // decrypt the result ciphertext
//    poseidon::Decryptor decryptor(context, keygen.secret_key());
//    double max = -1.0;
//    int max_idx = -1;
//    for (auto i = 0; i < result.size(); ++i) {
//        Ciphertext& ctxt_tmp = result[i];
//        Plaintext ptxt_tmp;
//        decryptor.decrypt(ctxt_tmp, ptxt_tmp);
//
//        std::vector<double> ans;
//        encoder.decode(ptxt_tmp, ans);
//
//        if (ans[0] > max && ans[0] >= 0.8) {
//            max = ans[0];
//            max_idx = i + 1;
//        }
//    }
//
//    // output max id
//    std::cout << "max id = " << max_idx << std::endl;
//}

//void software_test() {
//    ParametersLiteralDefault parm(CKKS,4096,poseidon::sec_level_type::none);
//    PoseidonContext context(parm, poseidon::sec_level_type::none, false);
//    double scale = pow(2.0, 32);
//
//    // input feature vector
//    std::string file1 = "/home/tangjiajian/Desktop/face_id/data1.txt";
//    std::string file2 = "/home/tangjiajian/Desktop/face_id/data2.txt";
//    std::string file3 = "/home/tangjiajian/Desktop/face_id/data3.txt";
//    poseidon::facial_recognition::FEATURE_VECTOR feat_vec(1024);
//    poseidon::facial_recognition::read_vector(file1, feat_vec);
//
//    // encode feature vector
//    poseidon::CKKSEncoder encoder(context);
//    Plaintext feat_vec_ptxt;
//    encoder.encode(feat_vec, scale, feat_vec_ptxt);
//    Plaintext ptxt;
//    encoder.encode(feat_vec, scale, ptxt);
//
//    poseidon::PublicKey public_key;
//    poseidon::RelinKeys relinKeys;
//    poseidon::GaloisKeys galoisKeys;
//
//    poseidon::KeyGenerator keygen(context);
//    keygen.create_public_key(public_key);
//    keygen.create_relin_keys(relinKeys);
//    keygen.create_galois_keys(std::vector<int>{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}, galoisKeys);
//
//    // encrypt feature vector into ciphertext
//    Ciphertext feat_vec_ctxt;
//    poseidon::Encryptor encryptor(context,public_key);
//    encryptor.encrypt(feat_vec_ptxt, feat_vec_ctxt);
//
//    // get the feature vector ciphertext
//    poseidon::CKKSEvaluator_S evaluator(context);
//    Ciphertext ctxt_temp;
//    evaluator.multiply_plain(feat_vec_ctxt, ptxt, ctxt_temp);
//    evaluator.rescale(ctxt_temp, ctxt_temp);
//    evaluator.drop_modulus_to_next(ctxt_temp, ctxt_temp);
//
//    // rotate
//    Ciphertext ctxt_result = ctxt_temp;
//    for (auto i = 1; i < 1024; i <<= 1) {
//        ctxt_temp = ctxt_result;
//        evaluator.rotate(ctxt_temp, i, galoisKeys, ctxt_temp);
//        evaluator.add(ctxt_result, ctxt_temp, ctxt_result);
//    }
//
//    // decrypt the result ciphertext
//    poseidon::Decryptor decryptor(context, keygen.secret_key());
//    Plaintext ptxt_tmp;
//    decryptor.decrypt(ctxt_result, ptxt_tmp);
//
//    std::vector<double> ans;
//    encoder.decode(ptxt_tmp, ans);
//
//    // output max id
//    std::cout << "result = " << ans[0] << std::endl;
//}

}