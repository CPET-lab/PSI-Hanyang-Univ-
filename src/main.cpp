#include "../include/main.h"

// CKKS params.
const int e_num = 16;
const int s_num = 59;
const double scale = pow(2.0, s_num);
const int N_num = 17;
const int depth = 41;

// PSI params.
const int dim = 128;
const int set_size = 256; // 256, 512, 1024
const double epsilon = pow(2.0, -e_num);
const int alpha = 66;

int main()
{
    // Modulus chain.
    vector<int> modulus = {60};
    for(int i=0; i<depth; i++)
        modulus.push_back(s_num);
    modulus.push_back(60);

    CKKS_params pms(modulus, e_num, s_num, N_num);

    // 파라미터 출력
    std::cout << "CKKS Parameters:\n";
    std::cout << std::format("| Precision e:\t2^-{}\n", e_num);
    std::cout << std::format("| Scale s:\t2^{}\n", s_num);
    std::cout << std::format("| Depth:\t{}\n", depth);
    std::cout << "PSI Parameters:\n";
    std::cout << std::format("| Dimension:\t{}\n", dim);
    std::cout << std::format("| Set Size:\t{}\n", set_size);
    std::cout << std::format("| Epsilon:\t2^-{}\n", e_num);
    std::cout << std::format("| Alpha:\t{}\n", alpha);
    std::cout << "------------\n";

    // Receiver and Sender data
    std::cout << "Generating data samples...\n";
    auto start_time = cur_time();
    std::pair<ddlist, ddlist> data_sample = make_data_sample(dim, set_size, set_size);
    auto end_time = cur_time();
    calculate_time(start_time, end_time);
    
    // TODO: Data modification of Receiver, Sender is not implemented yet.
    std::cout << "Encrypting data samples...\n";
    start_time = cur_time();
    ddlist receiver_set = data_sample.first;
    ddlist sender_set = data_sample.second;

    int size = receiver_set.size(); 
    std::vector<seal::Ciphertext> receiver_ctxts(size);
    std::vector<seal::Plaintext> sender_ptxts(size);
    seal::Plaintext pt;
    for(int i=0; i<size; i++)
    {
        pms.encoder->encode(receiver_set[i], scale, pt);
        pms.enc->encrypt(pt, receiver_ctxts[i]);
        pms.encoder->encode(sender_set[i], scale, sender_ptxts[i]);
    }
    end_time = cur_time();
    calculate_time(start_time, end_time);

    // 1. Cosine Similarity Calculation - Sum(pt*ct)
    std::cout << "Calculating Cosine Similarity...\n";
    start_time = cur_time();
    seal::Ciphertext sum_result, temp;
    pms.eva->multiply_plain(receiver_ctxts[0], sender_ptxts[0], sum_result);
    pms.eva->rescale_to_next_inplace(sum_result);

    for(int i=1; i<size; i++)
    {
        pms.eva->multiply_plain(receiver_ctxts[i], sender_ptxts[i], temp);
        pms.eva->rescale_to_next_inplace(temp);
        pms.eva->add_inplace(sum_result, temp);
    }
    end_time = cur_time();
    calculate_time(start_time, end_time);

    // 2. Sign Function Evaluation
    /*
        1. Calculate required interation numbers of f(x), g(x)
        2. Evaluate coeff_g_init
        3. Evaluate coeff_g iter(g) times
        4. Evaluate coeff_f iter(f) times
        5. Evaluate coeff_h
        6. Add 0.5
    */
    std::cout << "Calculating Sign Function...\n";
    start_time = cur_time();
    const int iter_g = std::ceil((1/std::log2(5850.0/1024.0)) * std::log2(1.0/epsilon)); // 7
    const int iter_f = std::ceil(0.5 * std::log2(alpha - 2)); // 3
    
    seal::Ciphertext sign_result = sum_result;
    evalPoly(pms, sign_result, coeff_g_init);
    for(int i=0; i<iter_g-1; i++)
    {
        evalPoly(pms, sign_result, coeff_g);
    }
    for(int i=0; i<iter_f-1; i++)
    {
        evalPoly(pms, sign_result, coeff_f);
    }
    evalPoly(pms, sign_result, coeff_h);
    pms.encoder->encode(0.5, sign_result.parms_id(), sign_result.scale(), pt);
    pms.eva->add_plain_inplace(sign_result, pt);
    end_time = cur_time();
    calculate_time(start_time, end_time);

    return 0;
}