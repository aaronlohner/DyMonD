# -*- coding: utf-8 -*-
#!/usr/bin/env python3
import sys
sys.path.insert(0,'/home/melsaa1/anaconda3/lib/python37.zip')
sys.path.insert(1,'/home/melsaa1/anaconda3/lib/python3.7')
sys.path.insert(2,'/home/melsaa1/anaconda3/lib/python3.7/lib-dynload')
sys.path.insert(3,'/home/melsaa1/anaconda3/lib/python3.7/site-packages')
print(sys.path)
import os
print("PYTHONPATH:", os.environ.get('PYTHONPATH'))
print("PATH:", os.environ.get('PATH'))
import pandas
import tensorflow as tf
import time
#from keras.models import Sequential, load_model
#from keras.utils import np_utils, to_categorical
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
#from keras.layers import Flatten, Conv2D, Dense, Softmax, Dropout, LSTM, Reshape
#from keras import optimizers
#from keras.layers.normalization import BatchNormalization
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.python.keras.utils import np_utils
from tensorflow.python.keras.utils.np_utils import to_categorical
from tensorflow.keras.layers import Flatten, Conv2D, Dense, Softmax, Dropout, LSTM, Reshape
from tensorflow.keras import optimizers
#from keras.layers.normalization import BatchNormalization
from tensorflow.keras.layers import BatchNormalization
def prediction(strinput):
    #config = ConfigProto()
    #config.gpu_options.allow_growth = True# uncomment if GPU would be used
    #session = InteractiveSession(config=config)
    # load model
    
    start_time = time.time()    
    model = load_model('NoSL18L1.h5')
    scaler = MinMaxScaler()   
    str1 = list(map(int, strinput.split()))
    tot = len(str1)
    row =int(tot/3600)
    #print(str)
    col=3600
    dataset= np.reshape(str1,(row,col)) 
    X_testN = dataset[:,0:3600].astype(float)
    '''
    mmin = np.zeros((3600,))
    mmax = np.array([253.0, 222.0, 174.0, 166.0, 246.0, 230.0, 249.0, 221.0, 226.0, 253.0, 184.0, 255.0, 204.0, 250.0, 218.0, 211.0, 213.0, 223.0, 215.0, 167.0, 238.0, 247.0, 219.0, 214.0, 250.0, 251.0, 246.0, 170.0, 237.0, 255.0, 216.0, 229.0, 241.0, 237.0, 173.0, 243.0, 253.0, 255.0, 254.0, 249.0, 255.0, 254.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 253.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 254.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 249.0, 253.0, 255.0, 254.0, 253.0, 253.0, 255.0, 254.0, 255.0, 253.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 250.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 255.0, 254.0, 254.0, 255.0, 255.0, 248.0, 254.0, 252.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 254.0, 255.0, 251.0, 254.0, 252.0, 255.0, 255.0, 255.0, 252.0, 253.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 254.0, 255.0, 251.0, 253.0, 254.0, 254.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 252.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 254.0, 251.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 253.0, 255.0, 254.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 250.0, 254.0, 255.0, 253.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 252.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 252.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 251.0, 255.0, 254.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 252.0, 255.0, 251.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 253.0, 255.0, 253.0, 252.0, 253.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 252.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 254.0, 254.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 250.0, 255.0, 253.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 253.0, 252.0, 255.0, 255.0, 249.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 249.0, 254.0, 255.0, 255.0, 255.0, 252.0, 255.0, 252.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 252.0, 253.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 254.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 252.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 250.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 252.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 254.0, 251.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 254.0, 253.0, 255.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 252.0, 253.0, 253.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 252.0, 253.0, 253.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 253.0, 255.0, 253.0, 255.0, 254.0, 253.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 253.0, 252.0, 251.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 254.0, 251.0, 255.0, 255.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 252.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 249.0, 255.0, 255.0, 254.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 252.0, 255.0, 255.0, 253.0, 252.0, 255.0, 254.0, 255.0, 249.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 253.0, 255.0, 252.0, 255.0, 253.0, 255.0, 255.0, 252.0, 252.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 252.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 253.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 251.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 253.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 253.0, 254.0, 255.0, 254.0, 252.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 252.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 251.0, 254.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 253.0, 255.0, 253.0, 255.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 250.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 254.0, 251.0, 253.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 252.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 251.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 251.0, 252.0, 254.0, 255.0, 254.0, 254.0, 254.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 250.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 254.0, 251.0, 255.0, 255.0, 255.0, 252.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 253.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 252.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 251.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 254.0, 255.0, 250.0, 255.0, 252.0, 254.0, 253.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 254.0, 254.0, 255.0, 254.0, 253.0, 255.0, 255.0, 252.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 252.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 253.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 252.0, 255.0, 255.0, 255.0, 253.0, 252.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 253.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 249.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 252.0, 254.0, 255.0, 255.0, 254.0, 252.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 252.0, 254.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 254.0, 255.0, 254.0, 255.0, 253.0, 255.0, 253.0, 252.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 252.0, 254.0, 251.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 253.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 254.0, 252.0, 255.0, 255.0, 254.0, 253.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 252.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 253.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 253.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 254.0, 254.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 251.0, 254.0, 255.0, 255.0, 255.0, 252.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 249.0, 255.0, 254.0, 253.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 252.0, 255.0, 254.0, 255.0, 255.0, 253.0, 251.0, 255.0, 254.0, 253.0, 251.0, 255.0, 255.0, 254.0, 254.0, 255.0, 253.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 251.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 254.0, 255.0, 253.0, 255.0, 255.0, 252.0, 255.0, 252.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 254.0, 255.0, 252.0, 251.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 254.0, 254.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 253.0, 254.0, 255.0, 255.0, 251.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0, 255.0, 252.0, 255.0, 255.0, 255.0, 252.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 255.0, 254.0, 255.0, 255.0, 254.0, 254.0, 254.0, 254.0, 255.0, 254.0, 254.0, 255.0, 255.0, 254.0, 253.0, 255.0, 255.0, 255.0, 255.0, 254.0, 252.0, 255.0, 252.0, 255.0, 252.0, 253.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 255.0, 254.0, 255.0, 254.0, 253.0, 254.0, 255.0, 255.0, 255.0, 255.0, 255.0, 253.0, 255.0, 255.0, 255.0])
    normalizedT = (X_testN - mmin) / (mmax - mmin)
    '''
    normalizedT = scaler.fit_transform(X_testN)
    t  = np.reshape(normalizedT, (len(normalizedT), 100, 6, 6))
    yhat_probs = model.predict_proba(t, verbose=0)
    # predict crisp classes for test set
    #yhat_classes = model.predict_classes(t, verbose=0)
    #yhat_classes_l = encoder.inverse_transform(yhat_classes)
    '''
    key_list = list(le_name_mapping.keys()) 
    val_list = list(le_name_mapping.values()) 
    '''
    #f = open("flows.csv","r")
    i=row

    y=""
    for c in range(i):
        j = np.argmax(yhat_probs[c])
        y=y+str(j)+" "+str(yhat_probs[c][j])+" "
    execution_time= time.time()-start_time
    print("execution time for the python script is: ")
    print(execution_time)

    return y

def main(argv=None):
    print("helloworld")
