from openfhe import *
import numpy as np
import time
import math
import torch

def sender_make_plaintext(cc, set_list, dim, set_iter, iteration_sign_function):
    pt_list = []
    for j in range(iteration_sign_function):
        pt_list.append([])
    
        for i in range(dim):
            pt_list[j].append(cc.MakeCKKSPackedPlaintext(np.repeat(set_list[j][i], set_iter)))
        
    return pt_list


def FPHC(cc, fhe_mode, receiver_set_enc, sender_element_list, dimension, ring_dim, scale_mod_size, alpha, epsilon, threshold, iteration_sign_function, ct_t = 0, acc = 0, queries = 2 ** 5, stat_param = 40):
    serType = BINARY
    temp = [0] * iteration_sign_function
    output = []
    for j in range(iteration_sign_function):
        start = time.time()
        #####
        for i in range(dimension):
            cosine = cc.EvalMult(receiver_set_enc[i], sender_element_list[j][i])
            temp[j] = cc.EvalAdd(cosine, temp[j])
        #####
        end = time.time()
            
        print("Breakdown of inner product",end-start)

        temp[j] = cc.EvalSub(temp[j], threshold)
#         temp[j] = cc.EvalMult(temp[j], 1/2) # computed in cipher_sign_func
        
        start = time.time()
        output.append(cipher_sign_func(cc, temp[j], alpha, epsilon))
        end = time.time()
        
        print("Breakdown of sign function",end-start)

        # nosie flooding
        if fhe_mode == EXEC_EVALUATION:
            ct_t_ = ct_t + acc

            sigma_star = math.sqrt(24 * queries * ring_dim) * (1 << (stat_param >> 1))
            sigma = sigma_star * ct_t_ * math.sqrt(ring_dim)
            err_samples = torch.randn(ring_dim >> 1, dtype=torch.float64)
            err = err_samples * (sigma / (1 << scale_mod_size))

            output[j] = cc.EvalAdd(output[j], cc.MakeCKKSPackedPlaintext(err.tolist()))
    
    return output


def cipher_sign_func(cc, ciphertext, alpha, epsilon): # n = 4, By Corollary 3 of (Efficient Homomorphic Comparison Methods with Optimal Complexity)
    iter_g = math.ceil((1/math.log(5850/1024,2)) * math.log(1/epsilon,2))
    iter_f = math.ceil(0.5 * math.log(alpha-2,2))
    x = ciphertext
    
    x = cc.EvalPoly(x,[0,5850/2048,0,-34974/8192,0,97015/32768,0,-113492/131072,0,46623/524288]) # compute g(x/2)
    
    for _ in range(iter_g - 1):
        x = cc.EvalPoly(x,[0,5850/1024,0,-34974/1024,0,97015/1024,0,-113492/1024,0,46623/1024])

    for i in range(iter_f - 1):
        x = cc.EvalPoly(x,[0,315/128,0,-420/128,0,378/128,0,-180/128,0,35/128])
        
    x = cc.EvalPoly(x,[0,315/256,0,-420/256,0,378/256,0,-180/256,0,35/256])
    x = cc.EvalAdd(x,0.5)

    return x