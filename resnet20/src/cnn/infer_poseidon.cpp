#include "infer_poseidon.h"

void import_parameters_cifar10(vector<double> &linear_weight, vector<double> &linear_bias, vector<vector<double>> &conv_weight, vector<vector<double>> &bn_bias, vector<vector<double>> &bn_running_mean, vector<vector<double>> &bn_running_var, vector<vector<double>> &bn_weight, size_t layer_num, size_t end_num)
{
	string dir;
	if(layer_num!=20 && layer_num!=32 && layer_num!=44 && layer_num!=56 && layer_num!=110) throw std::invalid_argument("layer number is not valid");
	if(layer_num == 20) dir = "resnet20_new";
	else if(layer_num == 32) dir = "resnet32_new";
	else if(layer_num == 44) dir = "resnet44_new";
	else if(layer_num == 56) dir = "resnet56_new";
	else if(layer_num == 110) dir = "resnet110_new";

	ifstream in;
	double val;
	size_t num_c = 0, num_b = 0, num_m = 0, num_v = 0, num_w = 0;

	conv_weight.clear();
	conv_weight.resize(layer_num-1);
	bn_bias.clear();
	bn_bias.resize(layer_num-1);
	bn_running_mean.clear();
	bn_running_mean.resize(layer_num-1);
	bn_running_var.clear();
	bn_running_var.resize(layer_num-1);
	bn_weight.clear();
	bn_weight.resize(layer_num-1);

	int fh = 3, fw = 3;
	int ci = 0, co = 0;

	// convolution parameters
	ci = 3, co = 16;
	in.open("../../pretrained_parameters/" + dir + "/conv1_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<fh*fw*ci*co; i++) {in>>val; conv_weight[num_c].emplace_back(val);} in.close(); num_c++;

	// convolution parameters
	for(int j=1; j<=3; j++)
	{
		for(int k=0; k<=end_num; k++)
		{
			// co setting
			if(j==1) co=16;
			else if(j==2) co=32;
			else if(j==3) co=64;

			// ci setting
			if(j==1 || (j==2 && k==0)) ci=16;
			else if((j==2 && k!=0) || (j==3 && k==0)) ci=32;
			else ci=64;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_conv1_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<fh*fw*ci*co; i++) {in>>val; conv_weight[num_c].emplace_back(val);} in.close(); num_c++;

			// ci setting
			if(j==1) ci = 16;
			else if(j==2) ci = 32;
			else if(j==3) ci = 64;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_conv2_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<fh*fw*ci*co; i++) {in>>val; conv_weight[num_c].emplace_back(val);} in.close(); num_c++;
		}
	}	

	// batch_normalization parameters
	ci = 16;
	in.open("../../pretrained_parameters/" + dir + "/bn1_bias.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<ci; i++) {in>>val; bn_bias[num_b].emplace_back(val);} in.close(); num_b++;
	in.open("../../pretrained_parameters/" + dir + "/bn1_running_mean.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<ci; i++) {in>>val; bn_running_mean[num_m].emplace_back(val);} in.close(); num_m++;
	in.open("../../pretrained_parameters/" + dir + "/bn1_running_var.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<ci; i++) {in>>val; bn_running_var[num_v].emplace_back(val);} in.close(); num_v++;
	in.open("../../pretrained_parameters/" + dir + "/bn1_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<ci; i++) {in>>val; bn_weight[num_w].emplace_back(val);} in.close(); num_w++;

	// batch_normalization parameters
	for(int j=1; j<=3; j++)
	{
		int ci;
		if(j==1) ci=16;
		else if(j==2) ci=32;
		else if(j==3) ci=64;

		for(int k=0; k<=end_num; k++)
		{
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_bias.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_bias[num_b].emplace_back(val);} in.close(); num_b++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_running_mean.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_running_mean[num_m].emplace_back(val);} in.close(); num_m++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_running_var.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_running_var[num_v].emplace_back(val);} in.close(); num_v++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn1_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_weight[num_w].emplace_back(val);} in.close(); num_w++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_bias.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_bias[num_b].emplace_back(val);} in.close(); num_b++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_running_mean.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_running_mean[num_m].emplace_back(val);} in.close(); num_m++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_running_var.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_running_var[num_v].emplace_back(val);} in.close(); num_v++;
			in.open("../../pretrained_parameters/" + dir + "/layer" + to_string(j) + "_" + to_string(k) + "_bn2_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
			for(long i=0; i<ci; i++) {in>>val; bn_weight[num_w].emplace_back(val);} in.close(); num_w++;
		}
	}

	// FC
	in.open("../../pretrained_parameters/" + dir + "/linear_weight.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<10*64; i++) {in>>val; linear_weight.emplace_back(val);} in.close();
	in.open("../../pretrained_parameters/" + dir + "/linear_bias.txt"); if(!in.is_open()) throw std::runtime_error("file is not open");
	for(long i=0; i<10; i++) {in>>val; linear_bias.emplace_back(val);} in.close();
}


void ResNet_cifar10_poseidon_sparse(size_t layer_num, size_t start_image_id, size_t end_image_id, uint32_t qdef)
{
	// approximation boundary setting
	double B = 40.0;	// approximation boundary

	// all threads output files
	ofstream out_share;
	if(layer_num == 20) out_share.open("../../result/resnet20_cifar10_label_" + to_string(start_image_id) + "_" + to_string(end_image_id));
	else if(layer_num == 32) out_share.open("../../result/resnet32_cifar10_label_" + to_string(start_image_id) + "_" + to_string(end_image_id));
	else if(layer_num == 44) out_share.open("../../result/resnet44_cifar10_label_" + to_string(start_image_id) + "_" + to_string(end_image_id));
	else if(layer_num == 56) out_share.open("../../result/resnet56_cifar10_label_" + to_string(start_image_id) + "_" + to_string(end_image_id));
	else if(layer_num == 110) out_share.open("../../result/resnet110_cifar10_label_" + to_string(start_image_id) + "_" + to_string(end_image_id));
	else throw std::invalid_argument("layer_num is not correct");


	uint32_t logN = 15;
	uint32_t logn = 14;		// full slots

    //Define constants for the bootstrap process
    auto q_def = qdef;
    ParametersLiteral ckks_param_literal{
            CKKS,
            logN,
            logn,
            q_def,
            5,
            1,
            0,
            {},
            {}
    };
    vector<uint32_t> logQTmp{28,27,31,31,31,31,31,31,31,31,  31,31,31,31,31,31,31,31,31,31,  31,31,31,31,31,31,31,31,31,31, 31,31,31,31,31,31,31,31,31,31, 31,31,31,31,31,31,31,31,31,31 ,31,31,31,31,31}; 
    vector<uint32_t> logPTmp{31,31,31,31,31,31,31,31,31,31,  31,31,31,31,31,31,31,31,31,31,  31,31,31,31,31,31,31,31,31,31, 31,31,31,31,31,31,31,31,31,31, 31,31,31,31,31,31,31,31,31,31 ,31,31,31,31,31};
    // ParametersLiteral ckks_param_literal(CKKS, logN, logn, logQTmp, logPTmp, q_def, 5,0,1);

    // CKKSParametersLiteralDefault ckks_param_literal(degree_32768);
    ckks_param_literal.set_log_modulus(logQTmp,logPTmp);
	PoseidonContext context(ckks_param_literal,poseidon::sec_level_type::none);
	// PoseidonContext context(ckks_param_literal,poseidon::sec_level_type::none,false);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    // GaloisKeys conjKeys;
    CKKSEncoder ckks_encoder(context);

    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
	auto secret_key = kgen.secret_key();
    kgen.create_relin_keys(relin_keys);
    // kgen.create_conj_keys(conjKeys);
    Encryptor encryptor(context,public_key, secret_key);
    Decryptor decryptor(context, secret_key);

    auto evaluator = EvaluatorFactory::SoftFactory()->create(context);

//	additional rotation kinds for CNN
	vector<int> rotation_kinds = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33
		// ,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55
		,56
		// ,57,58,59,60,61
		,62,63,64,66,84,124,128,132,256,512,959,960,990,991,1008
		,1023,1024,1036,1064,1092,1952,1982,1983,2016,2044,2047,2048,2072,2078,2100,3007,3024,3040,3052,3070,3071,3072,3080,3108,4031
		,4032,4062,4063,4095,4096,5023,5024,5054,5055,5087,5118,5119,5120,6047,6078,6079,6111,6112,6142,6143,6144,7071,7102,7103,7135
		,7166,7167,7168,8095,8126,8127,8159,8190,8191,8192,9149,9183,9184,9213,9215,9216,10173,10207,10208,10237,10239,10240,11197,11231
		,11232,11261,11263,11264,12221,12255,12256,12285,12287,12288,13214,13216,13246,13278,13279,13280,13310,13311,13312,14238,14240
		,14270,14302,14303,14304,14334,14335,15262,15264,15294,15326,15327,15328,15358,15359,15360,16286,16288,16318,16350,16351,16352
		,16382,16383,16384,17311,17375,18335,18399,18432,19359,19423,20383,20447,20480,21405,21406,21437,21469,21470,21471,21501,21504
		,22429,22430,22461,22493,22494,22495,22525,22528,23453,23454,23485,23517,23518,23519,23549,24477,24478,24509,24541,24542,24543
		,24573,24576,25501,25565,25568,25600,26525,26589,26592,26624,27549,27613,27616,27648,28573,28637,28640,28672,29600,29632,29664
		,29696,30624,30656,30688,30720,31648,31680,31712,31743,31744,31774,32636,32640,32644,32672,32702,32704,32706,32735
		,32736,32737,32759,32760,32761,32762,32763,32764,32765,32766,32767
	};

	cout << "Adding Bootstrapping Keys..." << endl;
	
    auto q0 = context.crt_context()->q0();

    auto level_start = ckks_param_literal.Q().size() - 1;

    EvalModPoly evalModPoly(context, CosDiscrete,(uint64_t)1 << 60 ,level_start-6, 10, 3, 16, 0, 30);
    auto scFac = evalModPoly.ScFac();
    double K = evalModPoly.K();
    auto qDiff = evalModPoly.QDiff();
    auto q0OverMessageRatio = exp2(round(log2((double)q0 / (double)evalModPoly.MessageRatio()) ) ) ;
    // If the scale used during the EvalMod step is smaller than Q0, then we cannot increase the scale during
    // the EvalMod step to get a free division by MessageRatio, and we need to do this division (totally or partly)
    // during the CoeffstoSlots step
    auto CoeffsToSlotsScaling = 1.0;
    CoeffsToSlotsScaling *= evalModPoly.qDiv() / (K * scFac * qDiff);

    auto SlotsToCoeffsScaling = ckks_param_literal.scale();
    SlotsToCoeffsScaling = SlotsToCoeffsScaling / ((double)evalModPoly.ScalingFactor() / (double)evalModPoly.MessageRatio() );

    HomomorphicDFTMatrixLiteral d(0, ckks_param_literal.LogN(), ckks_param_literal.LogSlots(), level_start, vector<uint32_t>(3,1), true, CoeffsToSlotsScaling, false, 1);
    HomomorphicDFTMatrixLiteral x(1, ckks_param_literal.LogN(), ckks_param_literal.LogSlots(),  26 , vector<uint32_t>(3,1), true, SlotsToCoeffsScaling, false, 1);
    LinearMatrixGroup mat_group;
    LinearMatrixGroup mat_group_dec;
    d.create(mat_group,ckks_encoder,2);
    x.create(mat_group_dec,ckks_encoder,1);

	vector<int> gal_steps_vector;
	gal_steps_vector.push_back(0);
	for(int i=0; i<logN-1; i++) gal_steps_vector.push_back((1 << i));
	for(auto rot: rotation_kinds)
	{
        auto temp = rot;
        // if(rot >= 16384)
        //     temp = rot - 16384;
		temp = rot % (1 << logn);
		if(find(gal_steps_vector.begin(), gal_steps_vector.end(), temp) == gal_steps_vector.end()) gal_steps_vector.push_back(temp);
	} 

	for(auto rot: mat_group.rot_index())
	{
        auto temp = rot;
		if(find(gal_steps_vector.begin(), gal_steps_vector.end(), temp) == gal_steps_vector.end()) gal_steps_vector.push_back(temp);
	} 
	
    kgen.create_galois_keys(gal_steps_vector, gal_keys);
	
	// time setting
	chrono::high_resolution_clock::time_point all_time_start, all_time_end;
	chrono::microseconds all_time_diff;
	all_time_start = chrono::high_resolution_clock::now();

	// end number
	int end_num = 0;		 
	if(layer_num == 20) end_num = 2;		// 0 ~ 2
	else if(layer_num == 32) end_num = 4;	// 0 ~ 4
	else if(layer_num == 44) end_num = 6;	// 0 ~ 6
	else if(layer_num == 56) end_num = 8;	// 0 ~ 8
	else if(layer_num == 110) end_num = 17;	// 0 ~ 17
	else throw std::invalid_argument("layer_num is not correct");

	#pragma omp parallel for num_threads(50)
	for(size_t image_id = start_image_id; image_id <=end_image_id; image_id++)
	{
		// each thread output result file
		ofstream output;
		if(layer_num == 20) output.open("../../result/resnet20_cifar10_image" + to_string(image_id) + ".txt");
		else if(layer_num == 32) output.open("../../result/resnet32_cifar10_image" + to_string(image_id) + ".txt");
		else if(layer_num == 44) output.open("../../result/resnet44_cifar10_image" + to_string(image_id) + ".txt");
		else if(layer_num == 56) output.open("../../result/resnet56_cifar10_image" + to_string(image_id) + ".txt");
		else if(layer_num == 110) output.open("../../result/resnet110_cifar10_image" + to_string(image_id) + ".txt");
		else throw std::invalid_argument("layer_num is not correct");
		string dir = "resnet" + to_string(layer_num) + "_new";

		// ciphertext pool generation
		vector<Ciphertext> cipher_pool(14);

		// time setting
		chrono::high_resolution_clock::time_point time_start, time_end, total_time_start, total_time_end;
		chrono::microseconds time_diff, total_time_diff;

		// variables
		TensorCipher cnn, temp;

		// deep learning parameters and import
		int co = 0, st = 0, fh = 3, fw = 3;
		long init_p = 4, n = 1<<logn;
		int stage = 0;
		double epsilon = 0.00001;
		vector<double> image, linear_weight, linear_bias;
		vector<vector<double>> conv_weight, bn_bias, bn_running_mean, bn_running_var, bn_weight;
		import_parameters_cifar10(linear_weight, linear_bias, conv_weight, bn_bias, bn_running_mean, bn_running_var, bn_weight, layer_num, end_num);

		// pack images compactly
		ifstream in;
		double val;
		in.open("../../testFile/test_values.txt");
		for(long i=0; i<1<<logn; i++) image.emplace_back(0);
		for(long i=0; i<32*32*3 *image_id; i++) {in>>val;}
		for(long i=0; i<32*32*3; i++) {in>>val; image[i]=val;}  in.close();
		for(long i=n/init_p; i<n; i++) image[i] = image[i%(n/init_p)];
		for(long i=0; i<n; i++) image[i] /= B;		// for boundary [-1,1]

		ifstream in_label;
		int image_label;
		in_label.open("../../testFile/test_label.txt");
		for(long i=0; i<image_id; i++) {in_label>>image_label;}
		in_label >> image_label;

		// generate CIFAR-10 image
		cnn = TensorCipher(logn, 1, 32, 32, 3, 3, init_p, image, encryptor, ckks_encoder, context);
		// decrypt_and_print(cnn.cipher(), decryptor, encoder, 1<<logn, 256, 2); cnn.print_parms();
		// cout << "remaining level : " << context.get_context_data(cnn.cipher().parms_id())->chain_index() << endl;
		// cout << "scale: " << cnn.cipher().scale() << endl;
		total_time_start = chrono::high_resolution_clock::now();

		// modulus down
		Ciphertext ctxt;
		ctxt = cnn.cipher();
		// for(int i=0; i<boot_level-3; i++) evaluator.mod_switch_to_next_inplace(ctxt);
		cnn.set_ciphertext(ctxt);

		// layer 0
		cout << "layer 0" << endl;
		output << "layer 0" << endl;
		
output << "------------------start-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

		multiplexed_parallel_convolution_print(cnn, cnn, 16, 1, fh, fw, conv_weight[stage], bn_running_var[stage], bn_weight[stage], epsilon, ckks_encoder, encryptor, evaluator, gal_keys, cipher_pool, output, decryptor, context, stage);
output << "------------------conv-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

		multiplexed_parallel_batch_norm_poseidon_print(cnn, cnn, bn_bias[stage], bn_running_mean[stage], bn_running_var[stage], bn_weight[stage], epsilon, ckks_encoder, encryptor, evaluator, B, output, decryptor, context, stage);
output << "------------------bn-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);
    
		approx_ReLU_poseidon_print(cnn, cnn, 0, encryptor, evaluator, decryptor, ckks_encoder, public_key, secret_key, relin_keys, B, output, context, gal_keys, stage);
output << "------------------relu-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);


		for(int j=0; j<3; j++)		// layer 1_x, 2_x, 3_x
		{
			if(j==0) co = 16;
			else if(j==1) co = 32;
			else if(j==2) co = 64;

			for(int k=0; k<=end_num; k++)	// 0 ~ 2/4/6/8/17
			{
				stage = 2*((end_num+1)*j+k)+1;
				cout << "layer " << stage << endl;
				output << "layer " << stage << endl;
				temp = cnn;

// 				if (0 == j && 0 == k)
// 				{					
// 					bootstrap_print(temp, temp, output, evaluator, evalModPoly, mat_group, mat_group_dec, relin_keys, gal_keys, decryptor, ckks_encoder, context, stage);
// output << "------------------bootstrap-----------------------" << endl;
// decrypt_and_print(output, temp.cipher(), decryptor, ckks_encoder, 1<<temp.logn(), 8, 8);
// 				}

				if(j>=1 && k==0) st = 2;
				else st = 1;

				multiplexed_parallel_convolution_print(cnn, cnn, co, st, fh, fw, conv_weight[stage], bn_running_var[stage], bn_weight[stage], epsilon, ckks_encoder, encryptor, evaluator, gal_keys, cipher_pool, output, decryptor, context, stage);
output << "------------------conv-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

				multiplexed_parallel_batch_norm_poseidon_print(cnn, cnn, bn_bias[stage], bn_running_mean[stage], bn_running_var[stage], bn_weight[stage], epsilon, ckks_encoder, encryptor, evaluator, B, output, decryptor, context, stage);
output << "------------------bn-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

				bootstrap_print(cnn, cnn, output, evaluator, evalModPoly, mat_group, mat_group_dec, relin_keys, gal_keys, decryptor, ckks_encoder, context, stage);
output << "------------------bootstrap-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);
				
				approx_ReLU_poseidon_print(cnn, cnn, 0, encryptor, evaluator, decryptor, ckks_encoder, public_key, secret_key, relin_keys, B, output, context, gal_keys, stage);
output << "------------------relu-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

        
				stage = 2*((end_num+1)*j+k)+2;
				cout << "layer " << stage << endl;
				output << "layer " << stage << endl;
				st = 1;

				multiplexed_parallel_convolution_print(cnn, cnn, co, st, fh, fw, conv_weight[stage], bn_running_var[stage], bn_weight[stage], epsilon, ckks_encoder, encryptor, evaluator, gal_keys, cipher_pool, output, decryptor, context, stage);
output << "------------------conv-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

				multiplexed_parallel_batch_norm_poseidon_print(cnn, cnn, bn_bias[stage], bn_running_mean[stage], bn_running_var[stage], bn_weight[stage], epsilon, ckks_encoder, encryptor, evaluator, B, output, decryptor, context, stage);
output << "------------------bn-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);
        
				if(j>=1 && k==0) 
				{
					multiplexed_parallel_downsampling_poseidon_print(temp, temp, evaluator, decryptor, ckks_encoder, context, gal_keys, output);
output << "------------------downsampling--------------------" << endl;
decrypt_and_print(output, temp.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);
				}
				
output << "------------------temp-----------------------" << endl;
decrypt_and_print(output, temp.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

output << "------------------cnn-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

				cipher_add_poseidon_print(temp, cnn, cnn, evaluator, output, decryptor, ckks_encoder, context);
        
output << "------------------before bootstrap--------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

				bootstrap_print(cnn, cnn, output, evaluator, evalModPoly, mat_group, mat_group_dec, relin_keys, gal_keys, decryptor, ckks_encoder, context, stage);
output << "------------------after bootstrap-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);
				
				approx_ReLU_poseidon_print(cnn, cnn, 0, encryptor, evaluator, decryptor, ckks_encoder, public_key, secret_key, relin_keys, B, output, context, gal_keys, stage);		
output << "------------------relu-----------------------" << endl;
decrypt_and_print(output, cnn.cipher(), decryptor, ckks_encoder, 1<<cnn.logn(), 8, 8);

			}
		}

		cout << "layer " << layer_num - 1 << endl;
		output << "layer " << layer_num - 1 << endl;
		averagepooling_poseidon_scale_print(cnn, cnn, evaluator, gal_keys, B, output, decryptor, ckks_encoder, context);
		fully_connected_poseidon_print(cnn, cnn, linear_weight, linear_bias, 10, 64, evaluator, gal_keys, output, decryptor, ckks_encoder, context);

		total_time_end = chrono::high_resolution_clock::now();
		total_time_diff = chrono::duration_cast<chrono::milliseconds>(total_time_end - total_time_start);

		// final text file print
		Plaintext plain;
		decryptor.decrypt(cnn.cipher(), plain);
		vector<complex<double>> rtn_vec;
		// encoder.decode(plain, rtn_vec, 1<<logn);
		ckks_encoder.decode(plain, rtn_vec);
		cout << "( "; 
		output << "( "; 
		for (size_t i = 0; i < 9; i++) {
			cout << rtn_vec[i] << ", ";
			output << rtn_vec[i] << ", ";
		}
		cout << rtn_vec[9] << ")" << endl;
		output << rtn_vec[9] << ")" << endl;
		cout << "total time : " << total_time_diff.count() / 1000 << " ms" << endl;
		output << "total time : " << total_time_diff.count() / 1000 << " ms" << endl;

		size_t label = 0;
		double max_score = -100.0;
		for(size_t i=0; i<10; i++)
		{
			if(max_score < rtn_vec[i].real())
			{
				label = i;
				max_score = rtn_vec[i].real();
			}
		}
		cout << "image label: " << image_label << endl;
		cout << "inferred label: " << label << endl;
		cout << "max score: " << max_score << endl;
		output << "image label: " << image_label << endl;
		output << "inferred label: " << label << endl;
		output << "max score: " << max_score << endl;
		out_share << "image_id: " << image_id << ", " << "image label: " << image_label << ", inferred label: " << label << endl;

	}

	all_time_end = chrono::high_resolution_clock::now();
	all_time_diff = chrono::duration_cast<chrono::milliseconds>(all_time_end - all_time_start);
	cout << "all threads time : " << all_time_diff.count() / 1000 << " ms" << endl;	
	out_share << endl << "all threads time : " << all_time_diff.count() / 1000 << " ms" << endl;

}