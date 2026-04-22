#include "../include/main.h"
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <chrono>

using namespace std;
using namespace std::chrono;

// CKKS params.
const int e_num = 16;
const int s_num = 59;
const double scale = pow(2.0, s_num);
const int N_num = 17;
const int depth = 42;

// PSI params. (이제 상수형으로 고정하지 않고 터미널 인자로 받습니다)
const double epsilon = pow(2.0, -e_num);
const int alpha = 66;

// debug params.
const bool print_result = false;
const bool check_time = false;

int main(int argc, char* argv[])
{
    // 1. 명령줄 인수 파싱 (-c, -s, -d)
    int c_log = 8;
    int s_log = 8;
    int d = 128; // Default dimension

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-c" && i + 1 < argc) c_log = stoi(argv[++i]);
        else if (arg == "-s" && i + 1 < argc) s_log = stoi(argv[++i]);
        else if (arg == "-d" && i + 1 < argc) d = stoi(argv[++i]);
    }

    int dim = d;
    int receiver_set_size = 1 << c_log; // 2^c_log
    int sender_set_size = 1 << s_log;   // 2^s_log

    std::cout << "CosSim FPSI Parameters:\n"
              << std::format("| Dimension (d):\t{}\n", dim)
              << std::format("| Client Size (Mc):\t2^{} ({})\n", c_log, receiver_set_size)
              << std::format("| Server Size (Ms):\t2^{} ({})\n", s_log, sender_set_size)
              << "------------\n";

    // ==========================================
    // [ Phase: OFFLINE ] - 파라미터 및 키 설정
    // ==========================================
    auto offline_start = cur_time();

    vector<int> modulus = {60};
    for(int i=0; i<depth; i++)
        modulus.push_back(s_num);
    modulus.push_back(60);

    CKKS_params pms(modulus, e_num, s_num, N_num);

    auto offline_end = cur_time();
    double offline_time = duration_cast<duration<double>>(offline_end - offline_start).count();


    // 데이터 샘플 생성 (시간 측정에서 제외)
    std::pair<ddlist, ddlist> data_sample = make_data_sample(dim, receiver_set_size, sender_set_size);
    std::pair<ddlist, ddlist> data_sample_modified = preprocess_data_sample(data_sample, receiver_set_size, sender_set_size);
    ddlist receiver_set = data_sample_modified.first;
    ddlist sender_set = data_sample_modified.second;


    // ==========================================
    // [ Phase: ONLINE ] - 실제 데이터 인코딩 및 프로토콜 평가
    // ==========================================
    auto online_start = cur_time();

    // 1. Client 질의 데이터 암호화
    seal::Plaintext pt;
    std::vector<seal::Ciphertext> receiver_ctxts(dim);
    for(int i=0; i<dim; i++)
    {
        pms.encoder->encode(receiver_set[i], scale, pt);
        pms.enc->encrypt(pt, receiver_ctxts[i]);
    }
    
    // 2. Server 데이터 평문 인코딩 (데이터 관여로 인한 Online 산입)
    std::vector<seal::Plaintext> sender_ptxts(dim);
    for(int i=0; i<dim; i++)
    {
        pms.encoder->encode(sender_set[i], scale, sender_ptxts[i]);
    }

    // 3. Cosine Similarity 연산 (Sum(pt*ct))
    seal::Ciphertext sum_result, temp;
    pms.eva->multiply_plain(receiver_ctxts[0], sender_ptxts[0], sum_result);
    pms.eva->rescale_to_next_inplace(sum_result);

    for(int i=1; i<dim; i++)
    {
        pms.eva->multiply_plain(receiver_ctxts[i], sender_ptxts[i], temp);
        pms.eva->rescale_to_next_inplace(temp);
        pms.eva->add_inplace(sum_result, temp);
    }

    // 4. Sign Function 평가
    const int iter_g = std::ceil((1/std::log2(5850.0/1024.0)) * std::log2(1.0/epsilon));
    const int iter_f = std::ceil(0.5 * std::log2(alpha - 2));
    
    seal::Ciphertext sign_result = sum_result;
    sign_result = evalPoly(pms, sign_result, coeff_g_init, print_result, check_time);
    for(int i=0; i<iter_g-1; i++) sign_result = evalPoly(pms, sign_result, coeff_g, print_result, check_time);
    for(int i=0; i<iter_f-1; i++) sign_result = evalPoly(pms, sign_result, coeff_f, print_result, check_time);
    sign_result = evalPoly(pms, sign_result, coeff_h, print_result, check_time);
    
    pms.encoder->encode(0.5, sign_result.parms_id(), sign_result.scale(), pt);
    pms.eva->add_plain_inplace(sign_result, pt);
    
    // 5. Client 결과 복호화
    pms.dec->decrypt(sign_result, pt);
    dlist decrypted_result;
    pms.encoder->decode(pt, decrypted_result);

    auto online_end = cur_time();
    double online_time = duration_cast<duration<double>>(online_end - online_start).count();


    // ==========================================
    // [ Phase: COMMUNICATION COST ] - 스트림 직렬화 기반 용량 측정
    // ==========================================
    
    // 1. Client -> Server (Query Ciphertexts)
    stringstream client_stream;
    receiver_ctxts[0].save(client_stream);
    double single_ct_size = client_stream.tellp();
    double query_size_bytes = single_ct_size * dim; // dim개의 암호문 전송

    // 2. Server -> Client (Response Ciphertext)
    stringstream server_stream;
    sign_result.save(server_stream);
    double response_size_bytes = server_stream.tellp(); // 평가가 완료된 암호문 1개 전송

    double total_comm_mb = (query_size_bytes + response_size_bytes) / (1024.0 * 1024.0);


    // ==========================================
    // [ Phase: CSV LOGGING ]
    // ==========================================
    bool file_exists = false;
    ifstream f("results.csv");
    if (f.good()) file_exists = true;
    f.close();

    ofstream out("results.csv", ios::app);
    if (!file_exists) {
        // 비교군 논문 양식에 맞춘 Header 출력 (Type, Threshold 제외)
        out << "Distance,Client_Log,Server_Log,Vec_Dim,Offline_Time(s),Online_Time(s),Communication(MB)\n";
    }
    
    out << "CosSim" << "," 
        << c_log << "," 
        << s_log << "," 
        << d << "," 
        << offline_time << "," 
        << online_time << "," 
        << total_comm_mb << "\n";
    out.close();

    std::cout << "Benchmark complete. Results appended to results.csv" << std::endl;

    return 0;
}