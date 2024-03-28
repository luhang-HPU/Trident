
#include "poseidon/PoseidonContext.h"
#include "poseidon/CKKSEncoder.h"
#include "poseidon/plaintext.h"
#include "poseidon/encryptor.h"
#include "poseidon/decryptor.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/precision.h"
#include "poseidon/Evaluator.h"
#include "poseidon/util/debug.h"
using namespace std;

using namespace poseidon;
using namespace poseidon::util;

int main() {

    cout << BANNER  << endl;
    cout << "POSEIDON SOFTWARE  VERSION:" <<POSEIDON_VERSION << endl;
    cout << "" << endl;

    ParametersLiteral ckks_param_literal{
            CKKS,
            15,
            14,
            40,
            5,
            0,
            0,
            {},
            {}
    };
    vector<uint32_t> logQTmp{31,31,31,31,31,31,31,31,31,31, 31,31,31,31,31,31,31,31,31,31};//,31,31,31,31}; //
    vector<uint32_t> logPTmp{31,31,31,31,31,31,31,31,31,31, 31,31,31,31,31,31,31,31,31,31};//,31,31,31,31}; //

    ckks_param_literal.set_log_modulus(logQTmp,logPTmp);
    PoseidonContext context(ckks_param_literal,poseidon::sec_level_type::none);

    //=====================init data ============================
    auto vec_size = ckks_param_literal.slot();
    double age, sbp, dbp, chl, height, weight;
    age = 26;
    sbp = 100;
    dbp = 70;
    chl = 100;
    height = 71;
    weight = 180;
    //输入个人身体参数，例：26, 100, 70, 100, 72, 180
    // printf("Please input your age:");
    // scanf("%lf", &age);
    // printf("\nPlease input your SBP:");
    // scanf("%lf", &sbp);
    // printf("\nPlease input your DBP:");
    // scanf("%lf", &dbp);
    // printf("\nPlease input your CHL:");
    // scanf("%lf", &chl);
    // printf("\nPlease input your height:");
    // scanf("%lf", &height);
    // printf("\nPlease input your weight:");
    // scanf("%lf", &weight);
    // printf("\n");

    //create message
    vector<complex<double>> message_age, message_sbp, message_dbp, message_chl, message_height, message_weight, vec_result;
    message_age.resize(vec_size);
    message_sbp.resize(vec_size);
    message_dbp.resize(vec_size);
    message_chl.resize(vec_size);
    message_height.resize(vec_size);
    message_weight.resize(vec_size);

    //message下标为0的地址存储对应身体数据的原始值
    message_age[0] = age;
    message_sbp[0] = sbp;
    message_dbp[0] = dbp;
    message_chl[0] = chl;
    message_height[0] = height;
    message_weight[0] = weight;

    //coef存储对应系数
    double coef_age = 0.072;
    double coef_sbp = 0.013;
    double coef_dbp = -0.029;
    double coef_chl = 0.008;
    double coef_height = -0.053;
    double coef_weight = 0.021;

    //taylor展开的系数
    double taylor_coef_0 = 1.0 / 2;
    double taylor_coef_1 = 1.0 / 4;
    double taylor_coef_3 = -1.0 / 48;
    double taylor_coef_5 = 1.0 / 480;
    double taylor_coef_7 = -17.0 / 80640;
    double taylor_coef_9 = 31 / 1451520;

    //=====================init  Plain & Ciph =========================
    Plaintext plain_age, plain_sbp, plain_dbp, plain_chl, plain_height, plain_weight, plain_result;
    Ciphertext cipher_age, cipher_sbp, cipher_dbp, cipher_chl, cipher_height, cipher_weight, cipher_x, cipher_x_square, cipher_result;
    PublicKey public_key;
    RelinKeys relinKeys;
    // GaloisKeys rotKeys;
    GaloisKeys conjKeys;
    // vector<uint32_t> rot_elemt;
    CKKSEncoder ckks_encoder(context);

    //=====================keys  =========================
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relinKeys);
    // kgen.create_galois_keys(steps,rotKeys);
    Encryptor enc(context,public_key,kgen.secret_key());
    Decryptor dec(context,kgen.secret_key());


    //-------------------encode--------------------------------
    ckks_encoder.encode(message_age,ckks_param_literal.scale(), plain_age);
    ckks_encoder.encode(message_sbp,ckks_param_literal.scale(), plain_sbp);
    ckks_encoder.encode(message_dbp,ckks_param_literal.scale(), plain_dbp);
    ckks_encoder.encode(message_chl, ckks_param_literal.scale(),plain_chl);
    ckks_encoder.encode(message_height,ckks_param_literal.scale(), plain_height);
    ckks_encoder.encode(message_weight,ckks_param_literal.scale(), plain_weight);

    //-------------------encrypt--------------------------------
    enc.encrypt(plain_age,cipher_age);
    enc.encrypt(plain_sbp,cipher_sbp);
    enc.encrypt(plain_dbp,cipher_dbp);
    enc.encrypt(plain_chl,cipher_chl);
    enc.encrypt(plain_height,cipher_height);
    enc.encrypt(plain_weight,cipher_weight);

    //-------------------------calculate----------------------------------
    //创建CKKS Evaluator

    auto ckks_eva = EvaluatorFactory::DefaultFactory()->create(context);

    auto start = chrono::high_resolution_clock::now();

    //计算 x = 0.072∙Age+0.013∙SBP-0.029∙DBP+0.008∙CHL-0.053∙height+0.021∙weight
    auto scale = ckks_param_literal.scale();
    ckks_eva->multiply_const(cipher_age, coef_age, scale,cipher_age,ckks_encoder);
    ckks_eva->multiply_const(cipher_sbp, coef_sbp, scale,cipher_sbp,ckks_encoder);
    ckks_eva->multiply_const(cipher_dbp, coef_dbp, scale,cipher_dbp,ckks_encoder);
    ckks_eva->multiply_const(cipher_chl, coef_chl, scale,cipher_chl,ckks_encoder);
    ckks_eva->multiply_const(cipher_height, coef_height, scale,cipher_height,ckks_encoder);
    ckks_eva->multiply_const(cipher_weight, coef_weight, scale,cipher_weight,ckks_encoder);

    ckks_eva->add(cipher_age, cipher_sbp, cipher_x);
    ckks_eva->add(cipher_x, cipher_dbp, cipher_x);
    ckks_eva->add(cipher_x, cipher_chl, cipher_x);
    ckks_eva->add(cipher_x, cipher_height, cipher_x);
    ckks_eva->add(cipher_x, cipher_weight, cipher_x);
    ckks_eva->rescale_dynamic(cipher_x,cipher_x,scale);


    //计算e^x/(e^x+1)
    ckks_eva->multiply_relin_dynamic(cipher_x, cipher_x, cipher_x_square, relinKeys);

    // gmp_printf("%.8Ff\n", cipher_x.metaData()->getScalingFactor().get_mpf_t()); //mpf_class
    // gmp_printf("%.8Ff\n", cipher_x_square.metaData()->getScalingFactor().get_mpf_t());
    ckks_eva->rescale_dynamic(cipher_x_square,cipher_x_square,scale);
    // gmp_printf("%.8Ff\n", cipher_x_square.metaData()->getScalingFactor().get_mpf_t());

    ckks_eva->multiply_const(cipher_x_square, taylor_coef_9, scale,cipher_result,ckks_encoder);
    printf("taylor_coef_9 cipher_result: %.8f\n", cipher_result.scale());
    ckks_eva->add_const(cipher_result, taylor_coef_7, cipher_result,ckks_encoder);
    printf("taylor_coef_7 cipher_result: %.8f\n", cipher_result.scale());


    ckks_eva->rescale_dynamic(cipher_result,cipher_result,scale);
    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relinKeys);
    ckks_eva->add_const(cipher_result, taylor_coef_5, cipher_result,ckks_encoder);


    ckks_eva->rescale_dynamic(cipher_result,cipher_result,scale);
    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relinKeys);
    ckks_eva->add_const(cipher_result, taylor_coef_3, cipher_result,ckks_encoder);


    ckks_eva->rescale_dynamic(cipher_result,cipher_result,scale);
    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x_square, cipher_result, relinKeys);
    ckks_eva->add_const(cipher_result, taylor_coef_1, cipher_result,ckks_encoder);


    ckks_eva->multiply_relin_dynamic(cipher_result, cipher_x, cipher_result, relinKeys);
    ckks_eva->add_const(cipher_result, taylor_coef_0, cipher_result,ckks_encoder);

    ckks_eva->read(cipher_result);
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "EXP TIME: " << duration.count() << " microseconds"<< endl;

    //---------------------decode & decrypt-------------------------------
    dec.decrypt(cipher_result, plain_result);
    ckks_encoder.decode(plain_result, vec_result);

    printf("answer after FHE = %.8f \n",real(vec_result[0]));

    //expected answer
    double x = coef_age * age + coef_sbp * sbp + coef_dbp * dbp + coef_chl * chl + coef_height * height + coef_weight * weight;

    printf("expected answer = %.8f \n",exp(x) / (exp(x) + 1));





    return 0;
}
