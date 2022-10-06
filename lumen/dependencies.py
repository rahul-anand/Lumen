# Initialising all required Libraries
import os

os.environ["RAY_OBJECT_STORE_ALLOW_SLOW_STORAGE"] = "1"
os.environ["MODIN_ENGINE"] = "ray"
import binascii

# patch_sklearn()
import cmath
import gc
import itertools
import json
import ntpath
import re
import shutil
import ssl
import string
import subprocess
import sys
import uuid
from collections import Counter
from importlib.machinery import SourceFileLoader
from io import BytesIO
from subprocess import call

import pandas as pd
import pypacker as ppy
from adlfs import AzureBlobFileSystem, AzureDatalakeFileSystem
from pypacker import ppcap
from ray.util.joblib import register_ray
from sklearn.pipeline import make_pipeline

# start_ray()
from tqdm import tqdm

# from sklearnex import patch_sklearn


ssl._create_default_https_context = ssl._create_unverified_context

import ast
import configparser
import importlib
import inspect
import json
import math

# from ray.ml.train.integrations.sklearn import SklearnTrainer
# from dask.distributed import Client, SSHCluster, LocalCluster
import multiprocessing as mp
import pickle
import subprocess
import time

# Importing all available Classifiers
from abc import ABC, abstractmethod

# import h2o
# Import time
from datetime import datetime, timedelta
from zipfile import ZipFile

import joblib

# import keras
import matplotlib.pyplot as plt
import more_itertools
import numpy as np
import pandas as pd

# import pyshark
import ray
import scipy

# import tensorflow as tf
import torch
import torch.nn.functional as F
import torchvision
from azure.storage.blob import BlobServiceClient
from flaml import AutoML

# from scapy.layers import *
from IPython.display import display

# from tf.keras.metrics import
from lumen.mapper import *
from psutil import virtual_memory
from scapy.all import *
from scipy.cluster.hierarchy import dendrogram, fcluster, linkage, to_tree
from scipy.fft import fft, ifft
from scipy.sparse.linalg import eigs

# Aggregate Functions
from scipy.stats import entropy
from sklearn.cluster import (
    DBSCAN,
    AgglomerativeClustering,
    FeatureAgglomeration,
    KMeans,
    MiniBatchKMeans,
    SpectralClustering,
)
from sklearn.ensemble import AdaBoostClassifier, IsolationForest, RandomForestClassifier
from sklearn.feature_selection import RFECV
from sklearn.linear_model import Lasso, LogisticRegression, RidgeClassifier

# Model evaluation Functions
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    pairwise_distances,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.mixture import GaussianMixture
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import BernoulliNB, GaussianNB
from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor

# All Feature Transformations
from sklearn.preprocessing import (
    LabelEncoder,
    MinMaxScaler,
    Normalizer,
    OneHotEncoder,
    OrdinalEncoder,
    RobustScaler,
    StandardScaler,
)
from sklearn.svm import SVC, LinearSVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils import resample
from sklearn.utils.validation import check_is_fitted

# # )
from torch.autograd import Variable

# from torch.monitor import Event
from torch.optim import SGD, Adadelta, Adagrad, Adam, RMSprop
from torchvision import transforms

# from utils.tools import getGaussianGram, timing
from xgboost import XGBClassifier
from xgboost_ray import RayDMatrix, RayParams, RayXGBClassifier, train
from zat.log_to_dataframe import LogToDataFrame

key = r"1DhbYErzDuLbwCofjivS0shRLATHbh3tUUwDjtcldFl6EbLfwdCuEksx1lGhOfOCJKDH0jHcpYzt+AStUePBWQ=="
service = BlobServiceClient(
    account_url="https://netsharecmu.blob.core.windows.net", credential=key
)
container_client = service.get_container_client("netsharecmu")

zipfilename = "rahul/pcaps/cicids2017/flows/Tuesday/pcaps/C001mc4UReJDop1D6l.pcap"
# print(zipfilename)
# blob_list = container_client.list_blobs(name_starts_with="rahul/")
# for blob in blob_list:
#     print("\t" + blob.name)
#     break
# # () + 1
# blob_data = container_client.download_blob(zipfilename)

# print(zipfilename)
# blob_bytes = blob_data.content_as_bytes()
# inmem = BytesIO(blob_bytes)
# print(inmem)
# inmem.seek(0)
# # bytes = inmem.read()
# # print(bytes)

# pcap = ppcap.Reader(inmem)
# pkt_count = 0
# val = -1
# for ts, packet in pcap:
#     print(ts, packet)

storage_options = {
    "account_name": "netsharecmu",
    "account_key": "1DhbYErzDuLbwCofjivS0shRLATHbh3tUUwDjtcldFl6EbLfwdCuEksx1lGhOfOCJKDH0jHcpYzt+AStUePBWQ==",
}
# AzureBlobFileSystem
# AzureDatalakeFileSystem
abfs = AzureBlobFileSystem(
    account_name="netsharecmu",
    container_name="netsharecmu",
    account_key="1DhbYErzDuLbwCofjivS0shRLATHbh3tUUwDjtcldFl6EbLfwdCuEksx1lGhOfOCJKDH0jHcpYzt+AStUePBWQ==",
    default_fill_cache=False,
    default_cache_type=None,
)

print(abfs)

print(abfs.ls("netsharecmu/rahul/"))
# ["netsharecmu/rahul/pcaps/cicids2017/flows/Tuesday/pcaps/C001mc4UReJDop1D6l.pcap"],


def sv_file(data):
    path, img = data
    print(path, img)
    return {"path": path, "text": img}


# pcaps/cicids2017/flows/Tuesday/pcaps/C001mc4UReJDop1D6l.pcap

# ds = ray.data.read_binary_files(
#     [
#         "netsharecmu/rahul/pcaps/cicids2017/flows/Tuesday/pcaps/C001mc4UReJDop1D6l.pcap",
#     ]
#     * 2000,
#     filesystem=abfs,
#     parallelism=20,
#     include_paths=True,
#     meta_provider=ray.data.datasource.FastFileMetadataProvider(),
#     ray_remote_args={"num_cpus": 0.25}
#     # num_cpus=0.2,
# )
# print(ds)
# results = ds.take_all()

# for key, val in results:
#     print(key, val)


# results = ds.map(sv_file)


# for i in ds.iter_rows():
#     print(i)
# print(ds.show())

# results = ds.map_batches(
#     sv_file, meta_provider=ray.data.datasource.FastFileMetadataProvider()
# )

# print(results)

# () + 1
# from keras.metrics import (
#     AUC,
#     Accuracy,
#     MeanSquaredError,
#     Precision,
#     Recall,
#     TrueNegatives,
#     TruePositives,
# )
# from keras.models import Model

from modin.utils import to_pandas

# from tensorflow.keras.callbacks import EarlyStopping, History
# from tensorflow.keras.layers import (
#     GRU,
#     BatchNormalization,
#     Concatenate,
#     Conv1D,
#     Dense,
#     Dropout,
#     GlobalMaxPooling1D,
#     GRUCell,
#     Input,
#     MaxPooling1D,
# )

# # from tensorflow.keras import load_model,save_model
# from tensorflow.keras.models import Model, Sequential


# import zipfile2


# , "lambda-3""/data/anaconda3/envs/mp3/bin/python"
# cluster = SSHCluster(["lambda-1", "lambda-2","lambda-4"],remote_python=["/home/wiselabadm/anaconda3/envs/mp3/bin/python","/home/wiselabadm/anaconda3/envs/mp3/bin/python","/home/wiselabadm/anaconda3/envs/mp3/bin/python"],worker_options={"nthreads": 10})
# client = Client(cluster)
# ()+1
# client = Client(processes=False)
# with LocalCluster(n_workers=int(0.9 * mp.cpu_count()),
#     processes=True,
#     # threads_per_worker=1,
#     # memory_limit='2GB',
#     # ip='tcp://localhost:9895',
# ) as cluster, Client(cluster) as client:
# with joblib.parallel_backend("dask",n_jobs=-1):
#     print(1)
#         # model.fit(data, y)

# ()+1


# import seaborn as sns


# from torch.nn import (
#     dense,
#     Conv1d,
#     Linear,
#     ReLU,
#     BatchNorm1d,
#     BatchNorm2d,
#     Sigmoid,
#     MaxPool1d,
#     MaxPool2d,
#     Module,
#     Sequential,
#     Dropout,
#     MSELoss,
#     CrossEntropyLoss,


# from ray.experimental import named_actors

# from scapy2dict import to_dict

# Writing a class for automatically fitting and tuning the model.


# from downcast import reduce


def clear_folder(sv_folder, mode=1):
    if os.path.exists(sv_folder):
        shutil.rmtree(sv_folder)
        # csv_path = self.parameters["save_directory"] + "/CSV/*/*"

        # files = glob(csv_path, recursive=True)

        # for f in files:
        #     try:
        #         os.remove(f)
        #         print(f)
        #     except OSError as e:
        #         print("Error: %s : %s" % (f, e.strerror))

        # files = glob(self.parameters["save_directory"] + "pdml_*", recursive=True)

        # for f in files:
        #     try:

        #         print(f)
        #     except OSError as e:
        #         print("Error: %s : %s" % (f, e.strerror))

        # else:
    if mode:
        os.makedirs(sv_folder)


def make_folder(new_svdir):
    if not os.path.exists(new_svdir):
        os.makedirs(new_svdir)



# import modin.pandas as pd1
import modin.experimental.pandas as pd1e
import modin.pandas as pd1
from modin.config import NPartitions, ProgressBar

ProgressBar.enable()
# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
pd.set_option("display.max_columns", 500)
pd.set_option("display.width", None)
print(NPartitions.get())
pd1.DEFAULT_NPARTITIONS = 30


print(ray.nodes())
print(ray.cluster_resources())


def my_random_string(string_length=3):
    """Returns a random string of length string_length."""
    random = str(uuid.uuid4())  # Convert UUID format to a Python string.
    random = random.upper()  # Make all characters uppercase.
    random = random.replace("-", "")  # Remove the UUID '-'.
    return random[0:string_length]  # Return the random string.


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def find_between_r(s, first, last):
    try:
        start = s.rindex(first) + len(first)
        end = s.rindex(last, start)
        return s[start:end]
    except ValueError:
        return ""


FE_prefix_old = "FE::"

FE_prefix = "FE_final::"

# from functionlist import functionlist as fl1

# ()+1
# from data_ingestion.datahandler import DataHandler
# from functions import *
# from data_ingestion.preprocessing import FlowBuilder
# from Trainer import Ensemble, GMM,metrics,OCSVM
# from feature_engineering.featurebuilder import feature_builder_OCSVM
# from feature_engineering.featuretransforms import Nystrom,KJL
# end_ray()

# ray.shutdown()

# ray.init(
#     address="ray://lambda-1:10001",
#     _redis_password="5241590000000000",
#     log_to_driver=True,
# )


def reduce(df):
    cols = df.dtypes.index.tolist()
    types = df.dtypes.values.tolist()
    dtype = {}
    for i, t in enumerate(types):
        if "int" in str(t):
            if (
                df[cols[i]].min() > np.iinfo(np.int8).min
                and df[cols[i]].max() < np.iinfo(np.int8).max
            ):
                df[cols[i]] = df[cols[i]].astype(np.int8)
                dtype[cols[i]] = np.int8
            elif (
                df[cols[i]].min() > np.iinfo(np.int16).min
                and df[cols[i]].max() < np.iinfo(np.int16).max
            ):
                df[cols[i]] = df[cols[i]].astype(np.int16)
                dtype[cols[i]] = np.int16
            elif (
                df[cols[i]].min() > np.iinfo(np.int32).min
                and df[cols[i]].max() < np.iinfo(np.int32).max
            ):
                df[cols[i]] = df[cols[i]].astype(np.int32)
                dtype[cols[i]] = np.int32

            else:
                df[cols[i]] = df[cols[i]].astype(np.int64)
                dtype[cols[i]] = np.int64

        elif "float" in str(t):
            if (
                df[cols[i]].min() > np.finfo(np.float16).min
                and df[cols[i]].max() < np.finfo(np.float16).max
            ):
                df[cols[i]] = df[cols[i]].astype(np.float16)
                dtype[cols[i]] = np.float16

            elif (
                df[cols[i]].min() > np.finfo(np.float32).min
                and df[cols[i]].max() < np.finfo(np.float32).max
            ):
                df[cols[i]] = df[cols[i]].astype(np.float32)
                dtype[cols[i]] = np.float32
            else:
                df[cols[i]] = df[cols[i]].astype(np.float64)
                dtype[cols[i]] = np.float64

        elif t == np.object:
            if cols[i] == "date":
                df[cols[i]] = pd.to_datetime(df[cols[i]], format="%Y-%m-%d")
            else:
                df[cols[i]] = df[cols[i]].astype("category")
    return df, dtype
