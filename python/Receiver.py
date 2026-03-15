from openfhe import *

def make_fhe_para(fhe_mode, mult_depth, scale_mod_size, batch_size, ring_dim):
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(scale_mod_size)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingTechnique(FLEXIBLEAUTOEXT)
    parameters.SetRingDim(ring_dim)

    parameters.SetSecurityLevel(HEStd_128_classic)
    parameters.SetExecutionMode(fhe_mode)
    
    if fhe_mode == EXEC_NOISE_ESTIMATION:
        parameters.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT)
        
    cc = GenCryptoContext(parameters)

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    
    return cc, keys


def decode_output(cc, sk, z, ringdim, set_size_r):
    split_set_s_num = ringdim // 2 // set_size_r
    
    output = []
    for i in range(len(z)):
        temp = cc.Decrypt(z[i],sk)
        temp = temp.GetCKKSPackedValue()

        for j in range(ringdim // 2):
            if temp[j].real > 0.5:
                output.append((j % set_size_r, j // set_size_r + i * split_set_s_num))
                
    return output