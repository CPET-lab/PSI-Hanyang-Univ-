#include "../include/CKKS_params.h"

void print_parameters(const SEALContext& context)
{
    auto& context_data = *context.key_context_data();
    string scheme_name = "CKKS";

    cout << "| Encryption parameters :" << endl;
    cout << "|   scheme: " << scheme_name << endl;
    cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "|   coeff_modulus size: ";
    cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    for (size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        cout << coeff_modulus[i].bit_count() << " + ";
    }
    cout << coeff_modulus.back().bit_count();
    cout << ") bits" << endl;
    cout << "---" << endl;
}

CKKS_params::CKKS_params(vector<int> modulus, int e_num, int s_num, int N)
{
    this->poly_modulus_degree = size_t(1) << N;
    parms = make_unique<EncryptionParameters>(scheme_type::ckks);
    parms->set_poly_modulus_degree(this->poly_modulus_degree);
   
    parms->set_coeff_modulus(CoeffModulus::Create(this->poly_modulus_degree, modulus));
    
    context = make_unique<SEALContext>(*parms, true, sec_level_type::none);
    keygen = make_unique<KeyGenerator>(*context);
    sk = keygen->secret_key();
    keygen->create_public_key(pk);
    keygen->create_relin_keys(rlk);

    enc = make_unique<Encryptor>(*context, pk);
    eva = make_unique<Evaluator>(*context);
    dec = make_unique<Decryptor>(*context, sk);
    encoder = make_unique<CKKSEncoder>(*context);
}

//두 암호문의 modulus 통일
void CKKS_params::modulus_equal(Ciphertext& ctxt1, Ciphertext& ctxt2)
{
    if(ctxt1.coeff_modulus_size() > ctxt2.coeff_modulus_size())
        eva->mod_reduce_to_inplace(ctxt1, ctxt2.parms_id());
    else if(ctxt1.coeff_modulus_size() < ctxt2.coeff_modulus_size())
        eva->mod_reduce_to_inplace(ctxt2, ctxt1.parms_id());
}
//두 암호문의 scale 통일
void CKKS_params::scale_equal(Ciphertext& ctxt1, Ciphertext& ctxt2)
{
    seal::Plaintext pt;
    while (ctxt1.coeff_modulus_size() > ctxt2.coeff_modulus_size()) {
        // eva->mod_reduce_to_inplace(ctxt1, ctxt2.parms_id());
        this->encoder->encode(1.0, ctxt1.parms_id(), ctxt1.scale(), pt);
        eva->multiply_plain_inplace(ctxt1, pt);
        eva->rescale_to_next_inplace(ctxt1);
    }

    while (ctxt1.coeff_modulus_size() < ctxt2.coeff_modulus_size()) {
        // eva->mod_reduce_to_inplace(ctxt2, ctxt1.parms_id());
        this->encoder->encode(1.0, ctxt2.parms_id(), ctxt2.scale(), pt);
        eva->multiply_plain_inplace(ctxt2, pt);
        eva->rescale_to_next_inplace(ctxt2);
    }
}
