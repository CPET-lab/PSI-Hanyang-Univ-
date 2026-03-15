import torch
import numpy as np

def make_data_sample(dim, receiver_set_size, sender_set_size):
    with open('receiver_set.txt', 'w') as f:
        for _ in range(receiver_set_size):
            vector = torch.randn(dim)
            vector = vector / torch.norm(vector, p=2)

            f.write(f"[{','.join(f'{x:.6f}' for x in vector)}] ")


    with open('sender_set.txt', 'w') as f:
        for _ in range(sender_set_size):
            vector = torch.randn(dim)
            vector = vector / torch.norm(vector, p=2)

            f.write(f"[{','.join(f'{x:.6f}' for x in vector)}] ")

def exact_fsi(receiver_set, sender_set, iteration_sign_function, dim, threshold, set_size_s, set_size_r):
    exact_output = []
    split_set_s_num = set_size_s // iteration_sign_function
    
    for k in range(iteration_sign_function):
        for j in range(split_set_s_num):
            temp_sum = np.array([0] * set_size_r)

            for i in range(dim):
                temp_sum = np.array(receiver_set[i]) * sender_set[k][i][j] + temp_sum

            for i in range(set_size_r):
                if temp_sum[i] > threshold:
                    exact_output.append((i,j + k * split_set_s_num))
                
    return exact_output

def open_set(dim, ring_dim):
    with open('receiver_set.txt', 'r') as f:
        data = f.read()
        receiver_list = data.split(" ")
        receiver_list.pop()

    set_size_r = len(receiver_list)

    for i in range(set_size_r):
        receiver_list[i] = eval(receiver_list[i])
    
    receiver_list = np.array(receiver_list)
    receiver_list = receiver_list.T
    receiver_list = receiver_list.tolist()
    
    
    with open('sender_set.txt', 'r') as f:
        data = f.read()
        sender_set = data.split(" ")
        sender_set.pop()

    set_size_s = len(sender_set)

    if (set_size_r * set_size_s) % (ring_dim // 2) != 0:
        print("(ring_dimension // 2) must divide (set_size_receiver * set_size_sender)")
        sys.exit(1)

    for i in range(set_size_s):
        sender_set[i] = eval(sender_set[i])

    sender_list = []

    iteration_sign_function = (set_size_r * set_size_s) // (ring_dim // 2)

    temp = set_size_s // iteration_sign_function

    for i in range(iteration_sign_function):
        temp_array = np.array(sender_set[i*temp:(i+1)*temp])
        temp_array = temp_array.T
        sender_list.append(temp_array.tolist())
        
    return receiver_list, sender_list, set_size_r, set_size_s, iteration_sign_function