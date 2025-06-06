#include "transformer.cpp"

int main()
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);

    cout << BANNER << endl;
    cout << "POSEIDON SOFTWARE  VERSION:" << POSEIDON_VERSION << endl;
    cout << "" << endl;

    uint32_t q_def = 40;
    ParametersLiteral ckks_param_literal{CKKS, 13, 12, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp{40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                             40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                             40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40};
    vector<uint32_t> logPTmp{40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                             40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
                             40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40};
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    PoseidonContext context =
        poseidon::PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto q0 = context.crt_context()->q0();

    // init random data
    int slots = 1 << ckks_param_literal.log_slots();

    // init Plain & Ciph
    PublicKey public_key;
    RelinKeys relinKeys;
    GaloisKeys conjKeys;
    GaloisKeys rotKeys;
    vector<uint32_t> rot_elemt;
    CKKSEncoder ckks_encoder(context);

    // keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);

    kgen.create_relin_keys(relinKeys);

    vector<int> gal_steps_vector;
    gal_steps_vector.push_back(0);
    for (int i = 0; i < ckks_param_literal.log_slots(); ++i)
    {
        gal_steps_vector.push_back(1 << i);
        gal_steps_vector.push_back(-(1 << i));
    }
    kgen.create_galois_keys(gal_steps_vector, rotKeys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    double scale = std::pow(2.0, q_def);

    vector<complex<double>> buffer1(16, 0);
    buffer1[0] = 0.13459576929391090569e-32;
    buffer1[1] = 24.558941542500461187;
    buffer1[2] = 0.48509566723824261626e-31;
    buffer1[3] = -669.66044971689436801;
    buffer1[4] = -0.24454123585384020859e-29;
    buffer1[5] = 6672.9984830133931554;
    buffer1[6] = 0.18687481194464005187e-28;
    buffer1[7] = -30603.665616389872425;
    buffer1[8] = -0.5762278175772426705e-28;
    buffer1[9] = 73188.403298778778129;
    buffer1[10] = 0.85368067300925938918e-28;
    buffer1[11] = -94443.321705008449291;
    buffer1[12] = -0.60270147469466762691e-28;
    buffer1[13] = 62325.409421254674884;
    buffer1[14] = 0.16234284366194031353e-28;
    buffer1[15] = -16494.674411780599848;

    Polynomial approxF1(buffer1, 0, 0, 16, Monomial);
    approxF1.lead() = true;
    // auto approxG = util::Approximate(g, a, b, deg);
    vector<Polynomial> poly_v1{approxF1};
    vector<vector<int>> slotsIndex1(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF1(context.parameters_literal()->degree() >> 1);

    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        // Index with all even slots
        idxF1[i] = i; 
    }

    // Assigns index of all even slots to poly[0] = f(x)
    slotsIndex1[0] = idxF1;

    PolynomialVector polys1(poly_v1, slotsIndex1);
    vector<complex<double>> buffer2(16, 0);

    buffer2[0] = 0.15326158858563023363e-46;
    buffer2[1] = 9.3562563603543978083;
    buffer2[2] = -0.36897212304824964462e-45;
    buffer2[3] = -59.163896393362639749;
    buffer2[4] = 0.17425439970330368218e-44;
    buffer2[5] = 148.86093062644842385;
    buffer2[6] = -0.32067211000221387429e-44;
    buffer2[7] = -175.8128748785829444;
    buffer2[8] = 0.27911573894864588724e-44;
    buffer2[9] = 109.11129968595543035;
    buffer2[10] = -0.12259030930610072562e-44;
    buffer2[11] = -36.676883997875556573;
    buffer2[12] = 0.26218914255796237778e-45;
    buffer2[13] = 6.3184629031129413078;
    buffer2[14] = -0.21666232642127535753e-46;
    buffer2[15] = -0.43711341508217764519;

    Polynomial approxF2(buffer2, 0, 0, 16, Monomial);
    approxF2.lead() = true;
    vector<Polynomial> poly_v2{approxF2};
    vector<vector<int>> slotsIndex2(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF2(context.parameters_literal()->degree() >> 1);

    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        // Index with all even slots
        idxF2[i] = i;
    }

    // Assigns index of all even slots to poly[0] = f(x)
    slotsIndex2[0] = idxF2;

    PolynomialVector polys2(poly_v2, slotsIndex2);
    vector<complex<double>> buffer3(28, 0);

    buffer3[0] = 0.6435519383199838375e-47;
    buffer3[1] = 5.078135697588612878;
    buffer3[2] = 0.81260103885576212533e-45;
    buffer3[3] = -30.732991813718681529;
    buffer3[4] = -0.16019847467842701065e-43;
    buffer3[5] = 144.10974681280942417;
    buffer3[6] = 0.10746315446051181804e-42;
    buffer3[7] = -459.66168882614256179;
    buffer3[8] = -0.36344872304451237262e-42;
    buffer3[9] = 1021.520644704596761;
    buffer3[10] = 0.72520712536978486691e-42;
    buffer3[11] = -1620.5625670887702504;
    buffer3[12] = -0.92730639785365506188e-42;
    buffer3[13] = 1864.6764641657026581;
    buffer3[14] = 0.79584309735406509106e-42;
    buffer3[15] = -1567.4930087714349494;
    buffer3[16] = -0.46919010314752753297e-42;
    buffer3[17] = 960.9703090934222369;
    buffer3[18] = 0.19086334965401618657e-42;
    buffer3[19] = -424.32616187164667827;
    buffer3[20] = -0.52743967802069637614e-43;
    buffer3[21] = 131.27850925600366538;
    buffer3[22] = 0.94704493797478696798e-44;
    buffer3[23] = -26.9812576626115819;
    buffer3[24] = -0.99818156176375019347e-45;
    buffer3[25] = 3.3065138731556502914;
    buffer3[26] = 0.46939046619219983164e-46;
    buffer3[27] = -0.18274294462753398785;

    // Polynomial approxF3(buffer3, 0, 0, 16, Monomial);
    Polynomial approxF3(buffer3, 0, 0, 28, Monomial);
    approxF3.lead() = true;
    // auto approxG = util::Approximate(g, a, b, deg);
    vector<Polynomial> poly_v3{approxF3};
    vector<vector<int>> slotsIndex3(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF3(context.parameters_literal()->degree() >> 1);

    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF3[i] = i;  // Index with all even slots
    }

    slotsIndex3[0] = idxF3;  // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys3(poly_v3, slotsIndex1);

    vector<complex<double>> vec_zero(context.parameters_literal()->slot(), 0);
    Plaintext plain_zero;
    Ciphertext ciph_zero;
    ckks_encoder.encode(vec_zero, context.parameters_literal()->scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_zero);

    vector<vector<complex<double>>> A(m, vector<complex<double>>(n, 0));
    vector<vector<complex<double>>> W_Q(n, vector<complex<double>>(k, 0));
    vector<vector<complex<double>>> W_K(n, vector<complex<double>>(k, 0));
    vector<vector<complex<double>>> W_V(n, vector<complex<double>>(k, 0));
    vector<Ciphertext> S(m, ciph_zero);

    srand(0);
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            A[i][j] = rand() / (RAND_MAX + 1.0);
        }
    }
    for (int i = 0; i < n; ++i)
    {
        for (int j = 0; j < k; ++j)
        {
            W_Q[i][j] = rand() / (RAND_MAX + 1.0);
            W_K[i][j] = rand() / (RAND_MAX + 1.0);
            W_V[i][j] = rand() / (RAND_MAX + 1.0);
        }
    }

    Attention(A, W_Q, W_K, W_V, S, polys1, polys2, polys3, ckks_encoder, enc, dec, ckks_eva,
              relinKeys, rotKeys, context);

    for (int i = 0; i < m; ++i)
    {
        Plaintext plain_ans;
        vector<complex<double>> ans(slots, 0);
        dec.decrypt(S[i], plain_ans);
        ckks_encoder.decode(plain_ans, ans);
        for (int j = 0; j < n; ++j)
        {
            cout << ans[j].real() << " ";
        }
        cout << endl;
    }

    return 0;
}
