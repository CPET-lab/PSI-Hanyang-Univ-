#pragma once
#include <vector>
#include <fstream>
#include <random>
#include <cmath>
#include <iomanip>
#include <string>
#include <format>
#include <cassert>
#include "CKKS_params.h"
#include "time.h"

#define dlist std::vector<double>
#define ddlist std::vector<std::vector<double>>

dlist coeff_g_init = {0, 5850.0/2048.0, 0, -34974.0/8192.0, 0, 97015.0/32768.0, 0, -113492.0/131072.0, 0, 46623.0/524288.0};
dlist coeff_g = {0, 5850.0/1024.0, 0, -34974.0/1024.0, 0, 97015.0/1024.0, 0, -113492.0/1024.0, 0, 46623.0/1024.0};
dlist coeff_f = {0, 315.0/128.0, 0, -420.0/128.0, 0, 378.0/128.0, 0, -180.0/128.0, 0, 35.0/128.0};
dlist coeff_h = {0, 315.0/256.0, 0, -420.0/256.0, 0, 378.0/256.0, 0, -180.0/256.0, 0, 35.0/256.0};


// Based on Construction.py/make_data_sample
std::pair<ddlist, ddlist> make_data_sample(int dim, int receiver_set_size, int sender_set_size)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<double> dist(0.0, 1.0);

    auto generate_normalized_vectors = [&](int set_size) -> ddlist
    {
        ddlist result;
        result.reserve(set_size);

        for (int i = 0; i < set_size; ++i) {
            dlist vec(dim);
            double norm = 0.0;

            for (int j = 0; j < dim; ++j) {
                vec[j] = dist(gen);
                norm += vec[j] * vec[j];
            }

            norm = std::sqrt(norm);

            for (int j = 0; j < dim; ++j) {
                vec[j] /= norm;
            }

            result.push_back(std::move(vec));
        }

        return result;
    };

    ddlist receiver_set = generate_normalized_vectors(receiver_set_size);
    ddlist sender_set = generate_normalized_vectors(sender_set_size);

    return {std::move(receiver_set), std::move(sender_set)};
}

// Duplicate, Transpose data
std::pair<ddlist, ddlist> preprocess_data_sample(std::pair<ddlist, ddlist> data_sample, int receiver_set_size, int sender_set_size)
{
    // For ease, we duplicate each data's row and transpose in the end.
    ddlist receiver_set = data_sample.first;
    ddlist sender_set = data_sample.second;

    // 1. Receiver data
    ddlist receiver_set_dup;
    receiver_set_dup.reserve(receiver_set_size * sender_set_size);
    for(int i=0; i<sender_set_size; i++)
    {
        for(int j=0; j<receiver_set_size; j++)
        {
            receiver_set_dup.push_back(receiver_set[j]);
        }
    }

    // 2. Sender data(Without permutation)
    ddlist sender_set_dup;
    sender_set_dup.reserve(receiver_set_size * sender_set_size);
    for(int i=0; i<sender_set_size; i++)
    {
        for(int j=0; j<receiver_set_size; j++)
        {
            sender_set_dup.push_back(sender_set[i]);
        }
    }

    // 3. Transpose
    int total_cols = receiver_set_size * sender_set_size;
    int dim = receiver_set[0].size();

    ddlist receiver_final(dim, dlist(total_cols));
    ddlist sender_final(dim, dlist(total_cols));

    for(int i=0; i<total_cols; i++)
    {
        for(int j=0; j<dim; j++)
        {
            receiver_final[j][i] = receiver_set_dup[i][j];
            sender_final[j][i] = sender_set_dup[i][j];
        }
    }

    assert (receiver_final.size() == dim && receiver_final[0].size() == total_cols);
    assert (sender_final.size() == dim && sender_final[0].size() == total_cols);
    
    return {std::move(receiver_final), std::move(sender_final)};
}

// Evaluate polynomial(Only degree=9 odd functions supported.)
// Same evaluation process to OPENFHE EvalPolyPS.
// ax^9 + bx^7 + cx^5 + dx^3 + ex
// = ax(x^8) + x^4(bx^3 + cx) + dx^3 + ex
// depth 4, cmult 6, pmult 5, add 4
seal::Ciphertext evalPoly(CKKS_params& pms, seal::Ciphertext& ct, dlist coeff, bool print_result=false, bool check_time=false)
{
    int start_level, end_level;
    std::chrono::_V2::system_clock::time_point start_time;
    std::chrono::_V2::system_clock::time_point end_time;

    const double a = coeff[9];
    const double b = coeff[7];
    const double c = coeff[5];
    const double d = coeff[3];
    const double e = coeff[1];
    seal::Plaintext pt_coeff;

    if(print_result) start_level = pms.context->get_context_data(ct.parms_id())->chain_index();
    if(check_time) start_time = cur_time();

    // 1. Create x^2, x^3, x^4
    seal::Ciphertext temp;
    seal::Ciphertext x, x2, x3, x4;
    x = ct;
    pms.eva->square(x, x2);
    pms.eva->relinearize_inplace(x2, pms.rlk);
    pms.eva->rescale_to_next_inplace(x2);

    temp = x;
    pms.scale_equal(temp, x2);
    // pms.eva->mod_reduce_to_inplace(temp, x2.parms_id());
    assert(temp.parms_id() == x2.parms_id() && temp.scale() == x2.scale());
    pms.eva->multiply(x2, temp, x3);
    pms.eva->relinearize_inplace(x3, pms.rlk);
    pms.eva->rescale_to_next_inplace(x3);

    pms.eva->square(x2, x4);
    pms.eva->relinearize_inplace(x4, pms.rlk);
    pms.eva->rescale_to_next_inplace(x4);

    // 2. Create term1 = ax * x^4 * x^4
    seal::Ciphertext term1;
    pms.encoder->encode(a, x.parms_id(), x.scale(), pt_coeff);
    pms.eva->multiply_plain(x, pt_coeff, term1);
    pms.eva->rescale_to_next_inplace(term1);

    for(int i=0; i<2; i++)
    {
        pms.scale_equal(term1, x4);
        pms.eva->multiply_inplace(term1, x4);
        pms.eva->relinearize_inplace(term1, pms.rlk);
        pms.eva->rescale_to_next_inplace(term1);
    }   

    // 3. Create term2 = x^4(bx^3 + cx)
    seal::Ciphertext term2;
    pms.encoder->encode(b, x3.parms_id(), x3.scale(), pt_coeff);
    pms.eva->multiply_plain(x3, pt_coeff, term2);
    pms.eva->rescale_to_next_inplace(term2);

    pms.encoder->encode(c, x.parms_id(), x.scale(), pt_coeff);
    pms.eva->multiply_plain(x, pt_coeff, temp);
    pms.eva->rescale_to_next_inplace(temp);

    pms.scale_equal(term2, temp);
    pms.eva->add_inplace(term2, temp);

    pms.scale_equal(term2, x4);
    pms.eva->multiply_inplace(term2, x4);
    pms.eva->relinearize_inplace(term2, pms.rlk);
    pms.eva->rescale_to_next_inplace(term2);

    // 4. Create term3 = dx^3 + ex
    seal::Ciphertext term3;
    pms.encoder->encode(d, x3.parms_id(), x3.scale(), pt_coeff);
    pms.eva->multiply_plain(x3, pt_coeff, term3);
    pms.eva->rescale_to_next_inplace(term3);

    pms.encoder->encode(e, x.parms_id(), x.scale(), pt_coeff);
    pms.eva->multiply_plain(x, pt_coeff, temp);
    pms.eva->rescale_to_next_inplace(temp);

    pms.scale_equal(term3, temp);
    pms.eva->add_inplace(term3, temp);

    // 5. Add term1, term2, term3
    pms.scale_equal(term1, term2);
    pms.eva->add_inplace(term1, term2);
    pms.scale_equal(term1, term3);
    pms.eva->add_inplace(term1, term3);
    if(print_result) end_level = pms.context->get_context_data(term1.parms_id())->chain_index();
    if(check_time) end_time = cur_time();
    
    //debug print
    if(print_result) std::cout << std::format("Level: {} -> {}\n", start_level, end_level);
    if(check_time) calculate_time(start_time, end_time);

    return term1;
}