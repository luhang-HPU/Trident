#include "test.h"

#include <thread>

#include "../backend_server/backend_server.h"
#include "../frontend_server/frontend_server.h"
#include "poseidon/util/debug.h"


namespace facial_recognition
{

void Test::test_open_frontend_and_backend()
{
    std::thread t1(&facial_recognition::BackendServer::run, &facial_recognition::BackendServer::getInstance());
    std::thread t2(&facial_recognition::FrontendServer::run, &facial_recognition::FrontendServer::getInstance());

    t1.join();
    t2.join();
}

void Test::test_main()
{
    auto &frontend_server = facial_recognition::FrontendServer::getInstance();
    auto &backend_server = facial_recognition::BackendServer::getInstance();

    // 同步Galois key
    nlohmann::json key_json;
    key_json["bytes"] = frontend_server.handler_galois_key();
    backend_server.handler_set_galois_key(key_json);

    // 读取人脸特征
//    facial_recognition::FEATURE_VECTOR feat_vec(1024);
//    facial_recognition::read_vector(get_file_path("data2.txt"), feat_vec);
    FEATURE_VECTOR feat_vec_sunninghui = {0.0112262, 0, 0.0195128, 0, 0.0376336, 0.0152859, 0.0279772, 0.00275262, 0.057239, 0.00693816, 0.0444341, 0.013377, 0.0118754, 0, 0.0208307, 0, 0.00742268, 0, 0, 0.0148319, 0, 0.00536427, 0.00799374, 0, 0, 0.0060592, 0.0419106, 0.00565668, 0.0192509, 0.0783361, 0.00823659, 0.0439998, 0, 0.00633695, 0, 0.0601722, 0.0624348, 0.0399104, 0.0074639, 0.0115478, 0.0127927, 0, 0.00646162, 0, 0.0101417, 0.00622149, 0.0234989, 0.0296149, 0, 0.0339915, 0.00562872, 0, 0.0118612, 0.0136232, 0.054075, 0, 0.0103444, 0.131631, 0.12241, 0.0592211, 0.00605528, 0.0125695, 0.00238968, 0.068018, 0.036598, 0.041166, 0, 0.0263295, 0.00849777, 0.0117667, 0, 0, 0, 0.0113431, 0.0088881, 0.0137776, 0.0106145, 0, 0, 0, 0.00592497, 0.0122359, 0.0049711, 0.00795151, 0.0125945, 0.0447915, 0.0399751, 0.00830965, 0.00281496, 0, 0.00782188, 0.012084, 0.0675562, 0.00613929, 0.0131319, 0.057639, 0.0472254, 0.0145369, 0.0244174, 0.0105429, 0, 0, 0, 0, 0, 0.0150868, 0, 0.00866901, 0.11485, 0.0111991, 0.0114574, 0, 0.0664967, 0, 0.010112, 0.0111216, 0.00991952, 0.0201217, 0, 0.0746839, 0, 0, 0, 0.0135948, 0.0622971, 0, 0, 0, 0.00165941, 0.0590559, 0, 0, 0.0146529, 0, 0, 0.01239, 0.0238262, 0, 0.0120375, 0.0570327, 0.0115257, 0.0100781, 0.0241195, 0, 0, 0.017495, 0, 0.0104959, 0.0494423, 0.0687379, 0.0669396, 0, 0, 0.0968865, 0, 0.129407, 0, 0, 0.0352802, 0.054119, 0, 0.00299922, 0, 0.0146864, 0.074629, 0.0100199, 0, 0, 0.00489515, 0, 0.0740453, 0.00853835, 0.00791581, 0, 0.085806, 0.0479476, 0.0383068, 0, 0.00356232, 0, 0, 0.0225863, 0, 0, 0.00143745, 0, 0.0109289, 0.00847619, 0, 0.00992483, 0, 0.068757, 0, 0.0332988, 0.00914463, 0, 0.0117684, 0, 0.0271616, 0, 0.00843179, 0.00889292, 0.136282, 0.0157097, 0, 0.0106584, 0, 0.00902004, 0, 0.0113992, 0.017041, 0.0130867, 0, 0, 0.0095072, 0.0136437, 0.0157594, 0, 0.0498604, 0.00735496, 0.0121768, 0.0437202, 0.0494326, 0, 0.0520476, 0.0167437, 0, 0.00741216, 0, 0.00651188, 0.0306201, 0.0142681, 0.0201, 0.00622711, 0, 0.0842576, 0.0376342, 0.000951402, 0, 0.0288715, 0.0207016, 0, 0.0892722, 0.0162524, 0.0497459, 0, 0.0108881, 0, 0.0108948, 0.00706537, 0.00794986, 0.0521188, 0.0115032, 0.0134674, 0.0448334, 0.0122927, 0.0092504, 0.0172977, 0.0182285, 0, 0.0379477, 0.114482, 0.0156397, 0.0132483, 0.0256217, 0.0222596, 0, 0.00362496, 0.0129615, 0.0090627, 0.0933865, 0, 0.00827694, 0.0123129, 0, 0.0111778, 0.0707921, 0.0143453, 0, 0.0380262, 0.00653614, 0.0103888, 0, 0, 0, 0.0743892, 0.0295288, 0, 0.030706, 0.0149626, 0.013642, 0.0514448, 0, 0, 0, 0.0571381, 0, 0.0131521, 0, 0.0047495, 0, 0.00656942, 0, 0.00397955, 0.0153635, 0.0128271, 0, 0, 0, 0.00262972, 0.0139512, 0, 0.0076716, 0.0134198, 0, 0, 0.0135528, 0.0270005, 0.0111271, 0, 0, 0, 0.0249139, 0.00914603, 0.00691871, 0.0219205, 0.0107972, 0.0125591, 0, 0, 0.0183776, 0.0253557, 0, 0.0815915, 0.0705275, 0, 0, 0, 0.0221963, 0.00462639, 0.00198759, 0.00924126, 0.0121411, 0.0185675, 0.0116287, 0.00896717, 0.00854916, 0.0132988, 0.0123441, 0.0132888, 0.0160013, 0, 0.0116619, 0, 0.00648633, 0, 0.00494694, 0, 0.00365121, 0.00800065, 0, 0, 0.0457537, 0, 0, 0.0160457, 0.100392, 0.0649038, 0, 0.0232141, 0.0246041, 0.011483, 0.00196708, 0, 0.148259, 0.0880838, 0.100109, 0.00810538, 0.00595669, 0.0363467, 0, 0, 0.0654143, 0.0150269, 0.00800041, 0, 0.0667625, 0.00629738, 0.0273491, 0.0305414, 0.0841502, 0.0165565, 0, 0.0814309, 0, 0, 0.0102991, 0.0353234, 0, 0, 0, 0.0131105, 0.0431058, 0.0139501, 0.00960266, 0.0134196, 0.00316623, 0, 0.0108775, 0, 0.0133969, 0, 0.0101733, 0.0242768, 0, 0.0552202, 0.0588181, 0, 0, 0.010522, 0.0179807, 0, 0.00442765, 0, 0, 0.0288539, 0.0163714, 0.0223164, 0, 0.0033404, 0.0595987, 0.0168455, 0.00169021, 0, 0.00456157, 0.00767813, 0.0237895, 0.0305483, 0, 0, 0, 0, 0.0104278, 0.00161772, 0.0165821, 0.0117935, 0.0108988, 0.0116834, 0.00642555, 0, 0.0438811, 0.0667883, 0.0245143, 0.0797309, 0, 0.035042, 0, 0, 0, 0.0279703, 0.00539345, 0.011565, 0, 0.103251, 0.0271737, 0.0116193, 0, 0, 0.011236, 0.00744061, 0, 0.0611562, 0.0162221, 0, 0.0711692, 0.058941, 0, 0.00807652, 0, 0.0110994, 0, 0.00994507, 0.011379, 0.0479702, 0.0179764, 0.0581287, 0, 0.0826549, 0, 0.0158925, 0.0130245, 0.011422, 0.00743271, 0.0653646, 0.00589231, 0.0246629, 0.0525403, 0.0122434, 0.0261383, 0.0101713, 0.0961954, 0.0418261, 0.022525, 0.0104138, 0, 0.00576891, 0.0586111, 0, 0.013289, 0.0024697, 0.00519532, 0.00653843, 0.0960612, 0.0251162, 0.0599999, 0.0210785, 0.0210551, 0, 0.00463694, 0.0193744, 0.00988678, 0, 0, 0, 0, 0.0222558, 0.02832, 0, 0, 0.0226599, 0, 0, 0, 0.0473367, 0, 0.0469614, 0.0584408, 0.0382411, 0, 0, 0, 0.0055657, 0.00714402, 0.00554751, 0.00491879, 0.0148446, 0, 0.0646672, 0, 0.0122651, 0, 0.0476944, 0.00633036, 0, 0, 0, 0.011396, 0.0114391, 0.0763549, 0, 0.0118827, 0.0146598, 0, 0.0867649, 0.0809219, 0.00873096, 0, 0, 0.00620815, 0.0135327, 0, 0, 0.00901447, 0.0110802, 0.0149057, 0, 0.0539679, 0.101728, 0.00346682, 0, 0.00483656, 0.0103798, 0.0244419, 0, 0.0110824, 0.0316907, 0.00705532, 0.0198359, 0.0104708, 0.031777, 0, 0, 0, 0.00695716, 0, 0, 0.01817, 0.0143433, 0.0275507, 0.00531242, 0.0358632, 0.00896898, 0, 0.00763409, 0, 0.0142936, 0.0966425, 0.00360807, 0.0137585, 0.00868232, 0, 0.0159333, 0.00604634, 0.012634, 0.0770461, 0.00695819, 0, 0.0114911, 0, 0, 0, 0.00698227, 0, 0, 0, 0.0603468, 0.0136879, 0, 0, 0, 0, 0.0530065, 0.040135, 0.00854262, 0, 0, 0.0269334, 0.03863, 0.0405669, 0, 0.00666179, 0.0133194, 0.0400045, 0.0469761, 0, 0.00490035, 0.00784918, 0, 0.00779168, 0.0150923, 0, 0.00799297, 0.0138303, 0, 0.0421277, 0.00900165, 0.0170238, 0, 0.0087681, 0.0410591, 0, 0, 0, 0, 0, 0.00893879, 0, 0, 0.057105, 0, 0.0803557, 0.0225019, 0, 0.00229266, 0.0141934, 0.0115783, 0.00907328, 0.0573707, 0.0650276, 0, 0.0923044, 0.0428984, 0.0102696, 0, 0, 0.022658, 0.0655338, 0.0167799, 0.0117197, 0.0220598, 0.0106865, 0, 0.0327333, 0, 0.0382265, 0, 0, 0.00558898, 0.0136376, 0.00486304, 0, 0.00176037, 0, 0, 0, 0, 0, 0.00186981, 0, 0.0242656, 0.0697335, 0, 0, 0.00838783, 0, 0.00901472, 0.00922313, 0.00398951, 0.00518192, 0.0118558, 0.019349, 0, 0.0140108, 0, 0, 0, 0, 0.014541, 0, 0, 0.0436388, 0, 0.0129501, 0.0105554, 0.00644869, 0.0924973, 0.00688978, 0, 0, 0.0251349, 0, 0, 0.0128292, 0.00902967, 0, 0.00577384, 0, 0.0717257, 0, 0, 0, 0, 0, 0.00740626, 0, 0.0421112, 0, 0.0348759, 0, 0, 0.0245651, 0, 0.0380853, 0.0235158, 0.00919255, 0, 0.00313975, 0.0659572, 0.0269579, 0.0605952, 0.0819121, 0, 0.0151164, 0, 0.131834, 0.0165502, 0.00324613, 0.00395406, 0.0129966, 0.0977248, 0.0166203, 0.0134947, 0.0265867, 0.0220365, 0.127576, 0.0492148, 0, 0.00354633, 0, 0, 0.0227438, 0.0619088, 0, 0.107296, 0.0120444, 0.00298098, 0.0364857, 0.0197349, 0.0938487, 0.0122815, 0, 0.0307125, 0, 0.00409196, 0.0111714, 0, 0.0454966, 0.0061882, 0.072852, 0, 0.0042479, 0, 0.0157533, 0, 0.0211671, 0, 0, 0.0112034, 0.0855491, 0.0405684, 0, 0, 0.0375686, 0, 0, 0.00934021, 0.0236842, 0, 0.0126546, 0.0201753, 0, 0.0115388, 0, 0.0427532, 0.0356685, 0.0113209, 0, 0.0124591, 0.016632, 0.0491728, 0.00973837, 0.0741751, 0, 0, 0, 0, 0, 0.0130122, 0.00562351, 0.0101005, 0.0519282, 0.0301679, 0.00616346, 0.0148612, 0.0173778, 0.0401539, 0.00544873, 0.00357531, 0, 0.00241252, 0.047905, 0, 0.0108193, 0.00243828, 0.0417811, 0, 0.0100311, 0, 0.0546503, 0.0116266, 0.00979588, 0, 0.0144343, 0.00487298, 0.0164206, 0.053391, 0.0406679, 0.0132719, 0, 0.0045223, 0.0548963, 0.0132643, 0.00918645, 0, 0, 0, 0.0145726, 0.0157425, 0.0834122, 0, 0.0157362, 0.0334836, 0.00174338, 0.032784, 0.079372, 0.0127586, 0.00932463, 0.011354, 0.0180051, 0.023082, 0.0511286, 0, 0.00650145, 0, 0.000840029, 0.00401899, 0, 0.00626648, 0, 0.00858703, 0, 0, 0.01483, 0.00583498, 0.0172417, 0.00212096, 0, 0.112513, 0.0114586, 0.0329854, 0, 0, 0, 0.0103309, 0.00866324, 0.0429176, 0, 0, 0.00485847, 0.0365584, 0.00572455, 0.0320674, 0.00808203, 0.0178471, 0, 0.011561, 0.00942974, 0.00674313, 0.0349823, 0.00899535, 0.00973749, 0.0163719, 0.054627, 0.00466401, 0, 0.0174551, 0.0551031, 0, 0.0117723, 0.0073166, 0.0299516, 0, 0, 0, 0.00778518, 0, 0, 0.0115458, 0.0728299, 0.0760129, 0, 0, 0.00604235, 0.092509, 0, 0, 0.0262451, 0, 0, 0, 0, 0.0208894, 0.082275, 0.00363263, 0, 0.00713181, 0.071099, 0.00442004, 0, 0, 0.0655368, 0.00443421, 0, 0.085832, 0.0886742, 0, 0.02498, 0, 0, 0.0483658, 0.00918712, 0.00372065, 0, 0.0548717, 0, 0, 0.0611464, 0.120698, 0.00493708, 0.0465591, 0.011033, 0, 0.00855482, 0, 0, 0, 0, 0, 0, 0.0419125, 0.0380985, 0.0613007, 0.106642, 0.0681643, 0, 0, 0, 0, 0.0065228, 0.00500527, 0.0520736, 0.0993227, 0.0172453, 0.057092};

    // 加密人脸特征
    nlohmann::json js_feat = feat_vec_sunninghui;
    nlohmann::json ciphertext_json;
    poseidon::util::Timestacs timer;
    timer.start();
    ciphertext_json["bytes"] = frontend_server.handler_feature_vector(js_feat);
    timer.end();
    timer.print_time_ms("handler_feature_vector");

    // 将人脸密文特征发送给后端服务器
    nlohmann::json ret_json = backend_server.handler_get_similarity_ciphertext(ciphertext_json);

    {
        poseidon::Plaintext plt;
        frontend_server.ptr_decryptor_->decrypt(backend_server.ctxt_, plt);
        std::vector<double> vec;
        frontend_server.encoder_.decode(plt, vec);
    }


    // 匹配人脸
    std::string max_id = frontend_server.handler_get_id(ret_json);

    if (max_id.empty())
    {
        std::cout << "no match" << std::endl;
    }
    std::cout << max_id << std::endl;
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