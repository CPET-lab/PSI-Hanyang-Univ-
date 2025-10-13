import Construction
import Sender
import Receiver
from openfhe import *
import math
import numpy as np
import time
import torch
import sys

def test(dim = 2 ** 7):
    ###################################sample a dataset###################################
    receiver_set_size = 2 ** 5
    sender_set_size = 2 ** 11
    Construction.make_data_sample(dim, receiver_set_size, sender_set_size)
    print("Make data sample(receiver_set.txt,sender_set.txt), set sizes :", receiver_set_size, ",",sender_set_size)
    print("Vector dimesion :", dim,"\n")
    
    
    ###################################setting parameter###################################
    alpha = 66
    epsilon = 2 ** (-16)

    if dim >= (1 << 9):
        threshold = 0.17
    elif dim >= (1 << 8):
        threshold = 0.23
    elif dim >= (1 << 7):
        threshold = 0.31
    elif dim >= (1 << 6):
        threshold = 0.45
    elif dim >= (1 << 5):
        threshold = 0.6
    else:
        threshold = 0.78

    mult_depth = 41
    scale_mod_size = 59
    batch_size = (131072 >> 1)
    ring_dim = 131072

    receiver_list, sender_list, set_size_r, set_size_s, iteration_sign_function = Construction.open_set(dim, ring_dim)

    iteration_r = ring_dim // (set_size_r << 1)
    iteration_s = ring_dim // ((set_size_s << 1) // iteration_sign_function)
    
    
    ###################################Protocol###################################
    receiver_runtime = 0
    sender_runtime = 0

    ct_t = (2 ** 9) * iteration_sign_function
    acc = (2 ** (scale_mod_size - (alpha - 1))) * iteration_sign_function

    start = time.time()
    cc, keys = Receiver.make_fhe_para(EXEC_EVALUATION, mult_depth, scale_mod_size, batch_size, ring_dim)
    end = time.time()
    preprocessing = end - start
    print("Time to Generate parameters(preprocessing):",preprocessing,"\n")


    start = time.time()
    sender_ptx = Sender.sender_make_plaintext(cc, sender_list, dim, iteration_s, iteration_sign_function)
    end = time.time()
    preprocessing = end - start
    print("Time of making pt_server(preprocessing):", preprocessing ,"\n")
    
    
    start = time.time()
    ###
    receiver_set_enc = [0] * dim
    for i in range(dim):
        receiver_set_enc[i] = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(receiver_list[i] * iteration_r))
    ###
    end = time.time()
    receiver_runtime = receiver_runtime + end - start
    print("Time of making ct_receiver:",receiver_runtime,"\n")

    
    start = time.time()
    ###
    z = Sender.FPHC(cc, EXEC_EVALUATION, receiver_set_enc, sender_ptx, dim, ring_dim, scale_mod_size, alpha, epsilon, threshold, iteration_sign_function, ct_t, acc)
    ###
    end = time.time()
    sender_runtime = sender_runtime + end - start


    print("\nEnd FPSI protocol\n")
    start = time.time()
    output = Receiver.decode_output(cc, keys.secretKey, z, ring_dim, set_size_r)
    end = time.time()
    receiver_runtime = receiver_runtime + end - start


    print("Communication :",((math.log2(9.066955176322703e+23) + scale_mod_size * mult_depth) * (ring_dim) / 8 / (2 ** 30) * (dim+1) * 2) + (math.log2(9.066955176322703e+23) * (ring_dim) / 8 / (2 ** 30) * iteration_sign_function * 2),"GB\n")

    print("Receiver's Runtime is",receiver_runtime)
    print("Sender's Runtime is",sender_runtime)


    exact_output = Construction.exact_fsi(receiver_list, sender_list, iteration_sign_function, dim, threshold, set_size_s, set_size_r)
    print("\nIndex of real intersection:")
    print(exact_output)

    print("Output index of Fuzzy PSI protocol:")
    print(output)

    print("\nThe output of the protocol is identical to that of the ideal functionality. :",set(exact_output) == set(output))
    

if __name__ == "__main__":
    try:
        dim = int(sys.argv[1])
        test(dim)
    except IndexError:
        test()
    except ValueError:
        print("Vector dimesion is always integer.")