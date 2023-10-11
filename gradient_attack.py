import os
import time
import csv
import sys
import yaml
import numpy as np
import pandas as pd
from src.util import ExeDataset, write_pred
from src.model import MalConv
from torch.utils.data import DataLoader
import torch
import torch.nn as nn
import torch.optim as optim
from torch.autograd import Variable
import pickle
import time


# Load config file for experiment

config_path = 'config/example.yaml' #needs to modify to point to a new list of valid label
seed = int(123)
conf = yaml.load(open(config_path, 'r'), Loader = yaml.SafeLoader)

use_gpu = conf['use_gpu']
use_cpu = conf['use_cpu']
exp_name = conf['exp_name'] + '_sd_' + str(seed)

valid_data_path = conf['valid_data_path']
valid_label_path = conf['valid_label_path']

checkpoint_dir = conf['checkpoint_dir']
chkpt_acc_path = checkpoint_dir + exp_name + '.model'

val_label_table = pd.read_csv(valid_label_path, header=None, index_col=0)

val_label_table.index = val_label_table.index.str.upper()
val_label_table = val_label_table.rename(columns={1: 'ground_truth'})



# empty_list = []
# list_of_file = val_label_table.index
# for lof in list_of_file:
#     add = "/home/user/Desktop/Attacks/data/valid/" + lof
#     try:
#         empty_list.append(os.path.getsize(add))
#     except:
#         continue
# print(empty_list)
# np.savetxt("File_size.csv", empty_list, delimiter=",", fmt='% d')
# exit()

val_table = val_label_table.groupby(level=0).last()
del val_label_table

validloader = DataLoader(ExeDataset(list(val_table.index), valid_data_path, list(val_table.ground_truth)),
                         batch_size=1, shuffle=False, num_workers=use_cpu)

malconv = torch.load('checkpoint/example_sd_123.model', map_location=torch.device('cpu'))

print("Loading MalConv model successful")

history = {}
history['val_loss'] = []
history['val_acc'] = []
history['val_pred'] = []
bce_loss = nn.BCEWithLogitsLoss()
total=0
evade = 0
changes=[]
temp_df = pd.DataFrame()

for _, val_batch_data in enumerate(validloader):
    total+=1
    cur_batch_size = val_batch_data[0].size(0)
    print("cur batch size:", cur_batch_size)

    exe_input = val_batch_data[0].cuda() if use_gpu else val_batch_data[0]

    data = exe_input[0].cpu().numpy()

    caveStart = data[-2]
    caveSize = data[-1]
    length = data[-3]

    data = data[:length]
    data = np.concatenate([data, np.random.randint(0, 256, 2000000 - length)])

    init_prob = 0

    #  temp_df[total] = pd.DataFrame(data)
    # # continue
 
    label = val_batch_data[1].cuda() if use_gpu else val_batch_data[1]
 
    label = Variable(label.float(), requires_grad=False)

    label = Variable(torch.from_numpy(np.array([[0]])).float(), requires_grad=False)

    embed = malconv.embed
    sigmoid = nn.Sigmoid()
    count_j = 0
    t=0

    for t in range(3):                                     
        exe_input = torch.from_numpy(np.array([data]))
        
        exe_input = Variable(exe_input.long(), requires_grad=False)

        pred = malconv(exe_input)
        
        prob = sigmoid(pred).cpu().data.numpy()[0][0]
        
        print("prob: ", prob)
        if t==0:
            init_prob = prob
        if prob < 0.5:
            print("prob<0.5,success.")
            evade+=1
            print("evading rate:",evade/float(total))
            break
        loss = bce_loss(pred, label)
        print("loss",loss)
        if length>=2000000:
            print("larger than 2MB")
            continue
        if (1.15*length) >=2000000:
            print("Perturbtation out of bound")
            continue
        loss.backward()
        w = malconv.embed_x.grad[0].data
        
        z = malconv.embed_x.data[0]

        print("Total malware size: ",length)
        print("Inserting the perturbation of size: ",int(0.15*length))

        for j in range(caveStart, caveStart+caveSize):
            if j % 1000 == 0:
                exe_input = torch.from_numpy(np.array([data]))
                exe_input = Variable(exe_input.long(), requires_grad=False)
                pred = malconv(exe_input)
                prob = sigmoid(pred).cpu().data.numpy()[0][0]
                print("prob: ", prob)
                count_j = j
                if prob < 0.5:
                    break
                print("changing " + str(j) + "th byte")

            try:
                min_index = -1
                min_di = int(caveSize)
                wj = -w[j:j + 1, :]
                nj = wj / torch.norm(wj, 2)
                zj = z[j:j + 1, :]
                for i in range(1, 256):
                    mi = embed(Variable(torch.from_numpy(np.array([i])))).data
                    si = torch.matmul((nj), torch.t(mi - zj))
                    di = torch.norm(mi - (zj + si * nj))
                    si = si.cpu().numpy()
                    if si > 0 and di < min_di:
                        min_di = di
                        min_index = i
                if min_index != -1:
                    data[j] = min_index
                    changes.append(min_index)
            except:
                continue
        print("finish ", t) 

    with open("data_15_cave_inside_txt_with_cave.csv", 'a') as file:
        writer = csv.writer(file)
        data = [val_batch_data, length, t, count_j, init_prob, prob ]
        writer.writerow(data)


    print("Reported result to a file")
