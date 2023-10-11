import pandas as pd
import numpy as np
import torch
from torch.utils.data import Dataset
import random

def write_pred(test_pred,test_idx,file_path):
    test_pred = [item for sublist in test_pred for item in sublist]
    with open(file_path,'w') as f:
        for idx,pred in zip(test_idx,test_pred):
            print(idx.upper()+','+str(pred[0]))

def check_malware(malware):
    df = pd.read_csv(r"/home/user/Desktop/Attacks/src/Cave15.csv")
    df.columns = ['Malware', 'Starting_address', 'Size', 'Status', 'Flag']
    match_row = 0
    try:
        match_row = df.loc[df['Malware']==malware]
        return (int(match_row['Starting_address']),int(match_row['Size']))
    except:
        return (0,0)

class ExeDataset(Dataset):
    def __init__(self, fp_list, data_path, label_list):
        self.fp_list = fp_list
        self.data_path = data_path
        self.label_list = label_list
        # self.first_n_byte = first_n_byte

    def __len__(self):
        return len(self.fp_list)

    def __getitem__(self, idx):
        try:
            with open(self.data_path+self.fp_list[idx],'rb') as f:
                tmp = [i+1 for i in f.read()]
                length=len(tmp)
                #tmp=tmp+[0]*(self.first_n_byte-len(tmp)-1)
                tmp=tmp+[length]
                # a,b = check_malware(self.fp_list[idx])
                # tmp = tmp + [a] + [b]
        except:
            with open(self.data_path+self.fp_list[idx].upper(),'rb') as f:
                tmp = [i+1 for i in f.read()]
                length = len(tmp)
                #tmp=tmp+[0]*(self.first_n_byte-len(tmp)-1)
                tmp=tmp+[length]
                # a,b = check_malware(self.fp_list[idx])
                # tmp = tmp + [a] + [b]

        return np.array(tmp),np.array([self.label_list[idx]])
 
