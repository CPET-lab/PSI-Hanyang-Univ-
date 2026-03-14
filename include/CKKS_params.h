#pragma once
#include "seal/seal.h"
#include "seal/bootstrapper.h"
using namespace std;
using namespace seal;


class CKKS_params {
public:
    // basic parameters
    size_t poly_modulus_degree;

    // CKKS parameters
    unique_ptr<EncryptionParameters> parms;
    vector<int> modulus;
    unique_ptr<SEALContext> context;
    unique_ptr<CKKSBootstrapper> boot;
    unique_ptr<KeyGenerator> keygen;
    SecretKey sk;
    PublicKey pk;
    RelinKeys rlk;

    // CKKS evaluation modules
    unique_ptr<Encryptor> enc;
    unique_ptr<Evaluator> eva;
    unique_ptr<Decryptor> dec;
    unique_ptr<CKKSEncoder> encoder;

    CKKS_params(vector<int> modulus, int e_num, int s_num, int N);

    // Plaintext encode(const double& input, Ciphertext& ctxt);
    // Plaintext encode(const double& input, Ciphertext& ctxt, double scale);
    // Plaintext encode(const vector<double>& input, Ciphertext& ctxt);
    // Plaintext encode(const vector<double>& input, Ciphertext& ctxt, double scale);
    // Ciphertext encrypt(const Plaintext& plain);
    // Ciphertext encrypt(const double& input, Ciphertext& ctxt);

    // Plaintext decrypt(Ciphertext& ctxt);
    // vector<double> decode(const Plaintext& ptxt);
    // vector<double> decode_ctxt(Ciphertext& ctxt);

    // void modulus_switch(Plaintext& ptxt, const parms_id_type parms_id);
    // void modulus_switch(Ciphertext& ctxt, const parms_id_type parms_id);
    // void add_ct_ct(Ciphertext& ctxt1, Ciphertext& ctxt2, Ciphertext& result);
    // void add_ct_ct_inplace(Ciphertext& ctxt1, Ciphertext& ctxt2);
    // void add_pt_ct_inplace(Plaintext& ptxt, Ciphertext& ctxt);
    // void add_pt_pt(Plaintext& pt1, Plaintext& pt2, Plaintext& result);
    // void add_pt_ct(seal::Plaintext& ptxt, seal::Ciphertext& ctxt, seal::Ciphertext& res);
    // void mult_ct_ct(Ciphertext& ctxt1, Ciphertext& ctxt2, Ciphertext& result);
    // void mult_ct_ct_inplace(Ciphertext& ctxt1, Ciphertext& ctxt2);
    // void mult_pt_ct(seal::Plaintext& ptxt, seal::Ciphertext& ctxt, seal::Ciphertext& res, bool rescale);
    // void mult_pt_ct_inplace(Plaintext& ptxt, Ciphertext& ctxt, bool rescale);
    // Ciphertext square(Ciphertext& ctxt);
    // void square_inplace(Ciphertext& ctxt);

    // Ciphertext exp(const Ciphertext& x, int d);
    void modulus_equal(Ciphertext& ctxt1, Ciphertext& ctxt2);
    void scale_equal(Ciphertext& ctxt1, Ciphertext& ctxt2);
    // void scale_equal(Plaintext& ptxt, Ciphertext& ctxt);
};