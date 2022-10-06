import glob as glob
import ntpath
from re import A
from string import ascii_letters, ascii_uppercase
from turtle import left

import tensorflow as tf
from lumen.dependencies import *
from numpy import float64
from scapy import fields
from tensorflow.core.framework.types_pb2 import DT_DOUBLE_REF
from tensorflow.python.keras.backend import conv1d
from tensorflow.python.keras.metrics import Accuracy, MeanAbsoluteError
from tensorflow.python.ops.gen_nn_ops import Conv2D


def df_transform(df_feat, mode=0):

    if type(df_feat) == pd1.DataFrame and mode == 1:
        print("To pandas")
        df_feat = df_feat._to_pandas()
    elif type(df_feat) == pd.DataFrame and mode == 0:
        df_feat = pd1.DataFrame(df_feat)

    return df_feat


@ray.remote(num_cpus=1)
class Rem(object):
    # from lumen.dependencies import *

    def __init__(self, parameters):

        self.parameters = parameters
        self.sleep = 5

    def kill(self):
        ray.actor.exit_actor()

    def pkt_read_tcptrace(
        self, flows, zip_path, layers, mapper, to_pass, svg, func_params
    ):

        bpath = os.path.dirname(zip_path)

        target_dir = "/tmp/"

        flist = []
        with ZipFile(zip_path) as zf:

            flist1 = []
            for counter, flow in enumerate(flows):
                if counter % 100 == 0:
                    print(counter, len(flows))
                lfor = flow + ".pcap"
                file = "pcaps/" + lfor
                flist1.append(file)

            print(len(flist1), "Extracting")

            zf.extractall(target_dir, members=flist1)

            print(len(flist1))

            df_merged = pd.DataFrame()
            counter = 0
            result = []

            for counter, flow in enumerate(flows):
                lfor = flow + ".pcap"
                file = "pcaps/" + lfor
                file1 = target_dir + "pcaps/" + flow + ".pcap"
                if not os.path.exists(file1):
                    print("Missing")

                    zf.extract(file, target_dir)

                tem_path = target_dir + "tcpdump_" + my_random_string() + ".csv"

                flist.append(file1)

                act_command = "tcptrace -l --csv {} > {}".format(file1, tem_path)
                colnames = [
                    "conn_#",
                    "host_a",
                    "host_b",
                    "port_a",
                    "port_b",
                    "first_packet",
                    "last_packet",
                    "total_packets_a2b",
                    "total_packets_b2a",
                    "resets_sent_a2b",
                    "resets_sent_b2a",
                    "ack_pkts_sent_a2b",
                    "ack_pkts_sent_b2a",
                    "pure_acks_sent_a2b",
                    "pure_acks_sent_b2a",
                    "sack_pkts_sent_a2b",
                    "sack_pkts_sent_b2a",
                    "dsack_pkts_sent_a2b",
                    "dsack_pkts_sent_b2a",
                    "max_sack_blks/ack_a2b",
                    "max_sack_blks/ack_b2a",
                    "unique_bytes_sent_a2b",
                    "unique_bytes_sent_b2a",
                    "actual_data_pkts_a2b",
                    "actual_data_pkts_b2a",
                    "actual_data_bytes_a2b",
                    "actual_data_bytes_b2a",
                    "rexmt_data_pkts_a2b",
                    "rexmt_data_pkts_b2a",
                    "rexmt_data_bytes_a2b",
                    "rexmt_data_bytes_b2a",
                    "zwnd_probe_pkts_a2b",
                    "zwnd_probe_pkts_b2a",
                    "zwnd_probe_bytes_a2b",
                    "zwnd_probe_bytes_b2a",
                    "outoforder_pkts_a2b",
                    "outoforder_pkts_b2a",
                    "pushed_data_pkts_a2b",
                    "pushed_data_pkts_b2a",
                    "SYN/FIN_pkts_sent_a2b",
                    "SYN/FIN_pkts_sent_b2a",
                    "req_1323_ws/ts_a2b",
                    "req_1323_ws/ts_b2a",
                    "adv_wind_scale_a2b",
                    "adv_wind_scale_b2a",
                    "req_sack_a2b",
                    "req_sack_b2a",
                    "sacks_sent_a2b",
                    "sacks_sent_b2a",
                    "urgent_data_pkts_a2b",
                    "urgent_data_pkts_b2a",
                    "urgent_data_bytes_a2b",
                    "urgent_data_bytes_b2a",
                    "mss_requested_a2b",
                    "mss_requested_b2a",
                    "max_segm_size_a2b",
                    "max_segm_size_b2a",
                    "min_segm_size_a2b",
                    "min_segm_size_b2a",
                    "avg_segm_size_a2b",
                    "avg_segm_size_b2a",
                    "max_win_adv_a2b",
                    "max_win_adv_b2a",
                    "min_win_adv_a2b",
                    "min_win_adv_b2a",
                    "zero_win_adv_a2b",
                    "zero_win_adv_b2a",
                    "avg_win_adv_a2b",
                    "avg_win_adv_b2a",
                    "initial_window_bytes_a2b",
                    "initial_window_bytes_b2a",
                    "initial_window_pkts_a2b",
                    "initial_window_pkts_b2a",
                    "ttl_stream_length_a2b",
                    "ttl_stream_length_b2a",
                    "missed_data_a2b",
                    "missed_data_b2a",
                    "truncated_data_a2b",
                    "truncated_data_b2a",
                    "truncated_packets_a2b",
                    "truncated_packets_b2a",
                    "data_xmit_time_a2b",
                    "data_xmit_time_b2a",
                    "idletime_max_a2b",
                    "idletime_max_b2a",
                    "hardware_dups_a2b",
                    "hardware_dups_b2a",
                    "throughput_a2b",
                    "throughput_b2a",
                    "Unnamed",
                ]

                os.system(act_command)

                df = pd.read_csv(tem_path, skiprows=9, names=colnames, header=None)

                df = df.drop(columns=["conn_#", "host_a", "host_b", "port_a", "port_b"])

                if counter % 100 == 0:
                    print(counter, df.shape, df)
                if df.shape[0] == 0:
                    new_row = {i: None for i in colnames}

                    df_dictionary = pd.DataFrame([new_row])
                    df = pd.concat([df, df_dictionary], ignore_index=True)

                df["flow_ID"] = flow
                record = df.to_dict(orient="records")

                if len(record) < 1:
                    print(df, record)
                    () + 1
                result.extend(record)
                os.remove(tem_path)

        df_merged = pd.DataFrame(result)

        print(df_merged.shape)
        print(df_merged.head())
        print(func_params)

        if df_merged.shape[0] == 0:
            return "-1"
        if "groupby" in func_params:
            groupby_param = func_params["groupby"]

            if groupby_param == "unidir":

                df_merged["sport"] = ports(
                    *[df_merged[i] for i in ["TCP__sport", "UDP__sport"]]
                )
                df_merged["dport"] = ports(
                    *[df_merged[i] for i in ["TCP__dport", "UDP__dport"]]
                )
                df_merged["concat"] = unidir(
                    *[
                        df_merged[i]
                        for i in ["IP__src_s", "IP__dst_s", "sport", "dport", "IP__p"]
                    ]
                )

            else:
                () + 1

            df_merged["flow_ID"] = df_merged["flow_ID"] + df_merged["concat"]

        df_merged.to_csv(svg, index=False)
        print("saved", svg)
        for file1 in flist:
            os.remove(file1)
        print("save]d", svg)

        time.sleep(5)

        return svg

    def pkt_read_flow(
        self, flows, zip_path, layers, mapper, to_pass, func_params, container_client
    ):
        def ports(v1, v2):
            temp = []
            for i1, i2 in zip(v1.tolist(), v2.tolist()):
                if i1 != -1:
                    temp.append(i1)
                else:
                    temp.append(i2)
            return np.array(temp)

        def unidir(*vector):
            df = pd.DataFrame()
            for i in vector:

                df = pd.concat([df, i], axis=1)
            print(df)
            df = df.fillna(0)

            for i in df.columns:
                df[i] = df[i].astype(str)

            df["concat_col"] = df.apply(lambda row: "-".join(row.tolist()), axis=1)

            return df["concat_col"]

        def fetcher(func2, pkt, ts, layer, packet):
            if func2 == "layers":

                g2g = [layer for layer in pkt]
                result = [o.__class__.__name__ for o in g2g]
                result = ",".join(result)

            elif func2 == "time":
                return ts

            elif func2 == "len":
                return len(pkt)

            elif func2 == "bytes":

                return list(packet)

            elif func2 == "src":

                return pkt.src

            elif func2 == "dst":

                return pkt.dst

            else:
                return getattr(pkt, func2, -1)

            return result

        bpath = os.path.dirname(zip_path)

        target_dir = "/tmp/"

        flist = []

        flist1 = []
        result = []

        for counter, flow in enumerate(flows):
            # print(counter, len(flows))
            # lfor = flow + ".pcap"
            file = f"{zip_path}{flow}.pcap"
            # DEST_FILE = "abc.pcap"
            # with open(DEST_FILE, "wb") as my_blob:
            #     print(file)
            #     download_stream = container_client.download_blob(file)
            #     my_blob.write(download_stream.readall())
            # # file = "pcaps/" + lfor
            flist1.append(file)
            pcap = ppcap.Reader(file)

            for ts, packet in pcap:
                # print(ts, packet)
                d1 = {}
                d1["flow_ID"] = flow
                pkt_eth = ppy.layer12.ethernet.Ethernet(packet)

                for layer, funs in layers.items():

                    layer_maps_to = mapper[layer]

                    temp = []
                    pkt1 = pkt_eth[eval(layer_maps_to)]

                    if layer == "packet":
                        for func1 in funs:

                            val = fetcher(func1, pkt_eth, ts, layer, packet)
                            d1[layer + "__" + func1] = val

                    else:
                        for func1 in funs:
                            val = getattr(pkt1, func1, -1)
                            d1[layer + "__" + func1] = val

                result.append(d1)
            pcap.close()
            # os.remove(DEST_FILE)
        df_merged = pd.DataFrame(result)

        print(df_merged.shape)
        print(df_merged.head())
        print(func_params)
        #     () + 1
        # () + 1

        # with ZipFile(zip_path) as zf:

        #     flist1 = []
        #     for counter, flow in enumerate(flows):
        #         print(counter, len(flows))
        #         lfor = flow + ".pcap"
        #         file = "pcaps/" + lfor
        #         flist1.append(file)

        #     print(len(flist1), target_dir, flist1, "Extracting")

        #     zf.extractall(target_dir, members=flist1)

        #     df_merged = pd.DataFrame()
        #     counter = 0
        #     result = []

        #     for counter, flow in enumerate(flows):
        #         lfor = flow + ".pcap"
        #         file = "pcaps/" + lfor
        #         file1 = target_dir + "pcaps/" + flow + ".pcap"
        #         if not os.path.exists(file1):
        #             print("Missing")

        #             zf.extract(file, target_dir)

        #         flist.append(file1)
        #         print(file1)
        #         pcap = ppcap.Reader(file1)

        #         for ts, packet in pcap:
        #             d1 = {}
        #             d1["flow_ID"] = flow
        #             pkt_eth = ppy.layer12.ethernet.Ethernet(packet)

        #             for layer, funs in layers.items():

        #                 layer_maps_to = mapper[layer]

        #                 temp = []
        #                 pkt1 = pkt_eth[eval(layer_maps_to)]

        #                 if layer == "packet":
        #                     for func1 in funs:

        #                         val = fetcher(func1, pkt_eth, ts, layer, packet)
        #                         d1[layer + "__" + func1] = val

        #                 else:
        #                     for func1 in funs:
        #                         val = getattr(pkt1, func1, -1)
        #                         d1[layer + "__" + func1] = val

        #             result.append(d1)
        #         pcap.close()

        # df_merged = pd.DataFrame(result)

        # print(df_merged.shape)
        # print(df_merged.head())
        # print(func_params)
        if df_merged.shape[0] == 0:
            return "-1"
            () + 1
        if "groupby" in func_params:
            groupby_param = func_params["groupby"]

            if groupby_param == "unidir":

                df_merged["sport"] = ports(
                    *[df_merged[i] for i in ["TCP__sport", "UDP__sport"]]
                )
                df_merged["dport"] = ports(
                    *[df_merged[i] for i in ["TCP__dport", "UDP__dport"]]
                )
                df_merged["concat"] = unidir(
                    *[
                        df_merged[i]
                        for i in ["IP__src_s", "IP__dst_s", "sport", "dport", "IP__p"]
                    ]
                )

            else:
                () + 1

            df_merged["flow_ID"] = df_merged["flow_ID"] + df_merged["concat"]

        # df_merged.to_csv(svg, index=False)
        # print("saved", svg)
        # for file1 in flist:
        #     os.remove(file1)
        # print("save]d", svg)

        # time.sleep()

        return df_merged

    def pkd_read_pypacker(self, layer, funs, file, csv_sv_path, mapper):
        def fetcher(func2, pkt, ts, layer, packet):
            if func2 == "layers":

                g2g = [layer for layer in pkt]
                result = [o.__class__.__name__ for o in g2g]
                result = ",".join(result)

            elif func2 == "time":
                return ts

            elif func2 == "len":
                return len(pkt)

            elif func2 == "bytes":
                return list(packet)

            else:
                return getattr(pkt, func2, -1)

            return result

        print(layer)
        print(funs)

        layer_maps_to = mapper[layer]

        result = []
        st = time.time()
        time.sleep(10)

        flag = 0
        for i in range(50):
            print("Waiting for file", file)
            if os.path.exists(file):
                flag = 1
                break
            time.sleep(1)

        if not os.path.exists(file):
            () + 1
            return -1
        print("wait finished")

        pcap = ppcap.Reader(filename=file)
        pkt_count = 0
        val = -1
        for ts, packet in pcap:

            pkt_count += 1
            pkt_eth = ppy.layer12.ethernet.Ethernet(packet)
            temp = []
            pkt1 = pkt_eth[eval(layer_maps_to)]
            if layer == "packet":
                for func1 in funs:

                    val = fetcher(func1, pkt_eth, ts, layer, packet)

                    temp.append(val)
            else:
                temp = [getattr(pkt1, o, -1) for o in funs]
            result.append(temp)

            if pkt_count % 100000 == 0:
                ctime = time.time()
                print(
                    "running",
                    temp,
                    ctime - st,
                    pkt_count,
                    (ctime - st) / pkt_count,
                    val,
                    len(result),
                    file,
                )

        df = pd.DataFrame(result)
        end = time.time()

        print(df.shape)

        if df.shape[0] == 0:
            return 1
        col_names = [layer + "__" + i for i in funs]

        df.columns = col_names

        df.to_csv(csv_sv_path, index=False)

        elapsed = end - st
        print("pypacker single core packet count:\t", pkt_count, len(result), elapsed)
        time.sleep(10)

        return 1

    def zeek_reader(self, file, sv_path, label, param):
        N = 20

        tem_path = (
            self.parameters["save_directory"]
            + "zeek_"
            + "".join(random.choices(string.ascii_uppercase + string.digits, k=N))
            + "/"
        )

        if not os.path.exists(tem_path):
            os.makedirs(tem_path)

        owd = os.getcwd()
        print(tem_path, owd, os.getcwd())
        os.chdir(tem_path)
        print(tem_path, os.getcwd())

        act_command = "/data/ray/zeek/zeek2/bin/zeek -r {} -C".format(file)
        print(act_command)

        os.system(act_command)

        os.chdir(owd)
        zeek_conn = tem_path + "conn.log"
        log_to_df = LogToDataFrame()
        zeek_df = log_to_df.create_dataframe(zeek_conn)

        zeek_df["ts"] = pd.to_datetime(zeek_df.index)
        zeek_df["duration"] = zeek_df["duration"].dt.total_seconds()

        zeek_df = zeek_df[param]

        zeek_df.columns = [f"FE::{i}" for i in zeek_df.columns]

        labels = [int(label == "Attacks")] * zeek_df.shape[0]

        zeek_df["Label"] = labels

        zeek_df.to_csv(sv_path, index=False)

        shutil.rmtree(tem_path)

        print("DOne overall", Counter(zeek_df["Label"]))
        time.sleep(self.sleep)

        return sv_path

    def nprint_reader(self, file, sv_path, label, param):
        act_command = "/data/ray/nprint-1.2.1/nprint -P {} {} -W {}".format(
            file, param, sv_path + "1.csv"
        )
        os.system(act_command)
        print("DOne and waiting to process\t", sv_path)
        df2 = pd.read_csv(sv_path + "1.csv", index_col=None, header=0)
        print("Finished reading CSV")
        os.remove(sv_path + "1.csv")

        keep_same = {"src_ip"}
        df2.columns = [
            f"FE_final::{i}" if i not in keep_same else f"{i}" for i in df2.columns
        ]
        labels = [label] * df2.shape[0]
        df2["index"] = df2.index
        df2["Label"] = labels

        print(df2.head(), df2.shape)

        df2.to_csv(sv_path, index=False)
        print("DOne overall", Counter(df2["Label"]))
        time.sleep(self.sleep)

        return sv_path

    def par_merge(self, df_feat, cl1, index):

        print(df_feat.shape, cl1)
        df_small = df_feat[cl1]
        to_ext = FE_prefix
        if FE_prefix_old not in cl1:
            df_new = pd.DataFrame(df_small)
            cols = []

            for i, value in enumerate(df_new.columns):
                new_v = cl1
                cols.append(new_v)
            df_new.columns = cols

        else:

            df_new = pd.DataFrame(df_small.values.tolist(), index=df_small.index)
            cols = []

            for i, value in enumerate(df_new.columns):
                new_v = to_ext + cl1 + "__" + str(i)
                cols.append(new_v)

            df_new.columns = cols

        df_new = df_new.reset_index(drop=True)

        print("Done\t", index, cl1, type(cl1), df_new.shape, df_new.columns)
        return df_new

    def wireshark_reader(self, file, sv_path, label, param, count):

        N = 5

        flag = 0
        for i in range(50):
            print("Waiting for file", file)
            if os.path.exists(file):
                flag = 1
                break
            time.sleep(5)

        tem_path = self.parameters["save_directory"] + "pdml_" + str(count) + "/"
        if not os.path.exists(tem_path):
            os.makedirs(tem_path)

        pdml_file = tem_path + "1.pdml"
        arff_file = tem_path + "1.arff"
        csv_file = tem_path + "1.csv"
        csv_file2 = tem_path + "12.csv"

        act_command = "/usr/bin/tshark -r {} -T pdml > {}".format(file, pdml_file)
        act_command1 = "python2 /data/ray/pdml/pdml2arff1.py {}  -n".format(pdml_file)
        print(act_command)
        print(act_command1)
        print(file, sv_path)

        os.system(act_command)

        print("Second Command")
        os.system(act_command1)

        print("DOne and waiting to process\n\n\n\n\n\n")
        sys.stdout.flush()

        with open(arff_file, "r") as inFile:
            content = inFile.readlines()
            name, ext = os.path.splitext(inFile.name)

            data = False
            header = ""
            new_content = []
            for line in content:
                if not data:
                    if "@ATTRIBUTE" in line or "@attribute" in line:
                        attributes = line.split()
                        if "@attribute" in line:
                            attri_case = "@attribute"
                        else:
                            attri_case = "@ATTRIBUTE"
                        column_name = attributes[attributes.index(attri_case) + 1]
                        header = header + column_name + ","
                    elif "@DATA" in line or "@data" in line:
                        data = True
                        header = header[:-1]
                        header += "\n"
                        new_content.append(header)
                else:
                    new_content.append(line)

            with open(csv_file, "w") as outFile:
                outFile.writelines(new_content)
        df2 = pd.read_csv(csv_file, na_values="?")
        del df2["class"]
        del df2["packet_id"]

        print(df2.head())

        print(df2.columns)
        df2.columns = [f"FE_final::{i}" for i in df2.columns]

        labels = [label] * df2.shape[0]

        df2["Label"] = labels
        df2 = df2.fillna(0)

        print(df2.head())

        print(df2.columns)
        shutil.rmtree(tem_path)

        df2.to_csv(sv_path, index=False)

        print("DOne overall", Counter(df2["Label"]))
        time.sleep(self.sleep)

        return sv_path


def par_merge(df_feat, cl1, index):

    print(df_feat.shape, cl1)
    to_ext = FE_prefix
    if FE_prefix_old not in cl1:
        df_new = pd1.DataFrame(df_feat[cl1])
        cols = []

        for i, value in enumerate(df_new.columns):
            new_v = cl1
            cols.append(new_v)
        df_new.columns = cols

    else:

        df_new = pd1.DataFrame(df_feat[cl1].values.tolist(), index=df_feat.index)
        cols = []

        for i, value in enumerate(df_new.columns):
            new_v = to_ext + cl1 + "__" + str(i)
            cols.append(new_v)

        df_new.columns = cols

    df_new = df_new.reset_index(drop=True)
    print("Done\t", index, cl1, type(cl1), df_new.shape)
    return df_new


laste = 0
cls = None


@ray.remote(max_calls=1)
def clear_ray():
    os.system(
        "ps aux | grep ray::IDLE | grep -v grep | awk '{print $2}' | xargs kill -9"
    )
    return 1


def ray_clear():
    res = []
    for i in range(5):
        res.append(clear_ray.remote())
    results = ray.get(res)

    return 1


def find_recent(results):

    keys = [i.split("_") for i in results.keys()]
    keys = sorted(keys, key=lambda x: x[-1], reverse=True)[0]
    return results["_".join(keys)]


def save_dict(di_, filename_):
    with open(filename_, "wb") as f:
        pickle.dump(di_, f)


def load_dict(filename_):
    with open(filename_, "rb") as f:
        ret_di = pickle.load(f)
    return ret_di


def save_row(parameters, inp_name, func_params, results=None):
    df1, ty1 = results[inp_name[0]]

    path = parameters["cur_row_svpath"]
    print("SAving\n", df1.shape, path, Counter(df1.Label), type(df1))

    filename, file_extension = os.path.splitext(path)

    if file_extension == ".csv":
        df1.to_csv(path)
    elif file_extension == ".pickle":
        df1.to_pickle(path)

    else:
        () + 1

    return 1, 1


def packet__protocol(vecctor):

    pass


def save(parameters, model, inp_name=[]):
    print("Inside save")

    path = parameters["save_directory"] + inp_name[0]
    os.makedirs(path, exist_ok=True)
    name = type(model).__module__.split(".")[0]
    print(name, type(model))
    sv_path = parameters["save_path"]

    path = path + "/" + model.__class__.__name__ + ".pickle"

    with open(path, "wb") as f:
        pickle.dump(model, f)

    print(sv_path)
    g_data = load_dict(sv_path)
    g_data["model_path"] = path
    print(g_data)

    save_dict(g_data, sv_path)

    return path


def tcptrace_extract(parameters, inp_name, func_params, results=None):

    count = parameters["packet_count"]

    train = DataHandler(
        path=parameters["data_path"],
        ndf=parameters["ndf_train"],
        fields=[],
        count=parameters["packet_count"],
        distributed=parameters["distributed"],
        data_mode=parameters["data_mode"],
        parameters=parameters,
        func_params=func_params,
    ).d_custom(mode="tcptrace")
    return train, type(train)


def zeek_extract(parameters, inp_name, func_params, results=None):

    count = parameters["packet_count"]

    train = DataHandler(
        path=parameters["data_path"],
        ndf=parameters["ndf_train"],
        fields=[],
        count=parameters["packet_count"],
        distributed=parameters["distributed"],
        data_mode=parameters["data_mode"],
        parameters=parameters,
        func_params=func_params,
    ).dzeek(mode="zeek")
    return train, type(train)


def get_num_packets(file):
    st = time.time()

    count = 0
    pcap = ppcap.Reader(filename=file[0])
    pkt_count = 0
    for ts, packet in pcap:
        pkt_count += 1
    pcap.close()
    end = time.time()

    elapsed = end - st
    print("Elapsed in counting", elapsed)

    return pkt_count


def count(vector):
    temp = list(vector)

    return len(temp)


def tbytes(vector):

    a = vector.apply(lambda x: len(x))

    return a.sum()


def packet_direction(*args):

    df = pd.DataFrame()
    for i in args:
        df = pd.concat([df, i], axis=1)

    flowid = df.columns
    flowid = [i.strip() for i in flowid]

    df["direction"] = 1
    df["FID"] = np.nan
    df["FID"] = df["FID"].astype(object)

    swap = {
        "IP__src_s": "IP__dst_s",
        "IP__dst_s": "IP__src_s",
        "sport": "dport",
        "dport": "sport",
    }

    g = df.groupby(flowid, as_index=True)
    device_id = list(g.groups.keys())
    print("The total number of unidirectional flows are", len(device_id))
    print(flowid, g, type(g))

    fid = []
    if "IP__src_s" in flowid:
        fid.extend(["IP__src_s", "IP__dst_s"])
        flowid.remove("IP__src_s")

    if "IP__dst_s" in flowid:
        if "IP__dst_s" not in fid:
            fid.extend(["IP__src_s", "IP__dst_s"])
        flowid.remove("IP__dst_s")

    if "sport" in flowid:
        fid.extend(["sport", "dport"])
        flowid.remove("sport")

    if "dport" in flowid:
        if "dport" not in fid:
            fid.extend(["sport", "dport"])
        flowid.remove("dport")

    fid.extend(flowid)
    flowid = fid.copy()

    for j in g.groups.keys():
        if type(j) == "str":
            i = [j]
        else:
            i = j
        i2 = []
        c = 0
        if "IP__src_s" in flowid:
            i2 = [i[1], i[0]]
            c = 1
        if "sport" in flowid:
            i2 = i2 + [i[3], i[2]]
            c = 3
        if len(i) > c + 1:
            i2 = i2 + list(i)

        i2 = tuple(i2)

        temp = list(g.groups[i])

        df.loc[temp, "direction"] = 1

        if (i2 in device_id) & (i != i2):
            temp = list(g.groups[i2])
            df.loc[temp, "direction"] = -1

    print(df["direction"].unique())

    return df["direction"]


def direction(*args):
    df = pd.DataFrame()
    for i in args:
        print(i)
        df = pd.concat([df, i], axis=1)

    df["direction"] = 1

    g = df.groupby(by=["flow_ID"], as_index=True)
    connections = list(g.groups.keys())

    for flowname, grp in g:
        uflows = grp.groupby(by=["IP__src_s"], as_index=True)

        ips = list(uflows.groups.keys())
        l = len(ips)

        if l == 2:
            idx = uflows.groups[ips[1]]
            df.loc[idx, "direction"] = -1

    return df["direction"]


def direction1(*args):
    df = pd.DataFrame()
    for i in args:
        print(i)
        df = pd.concat([df, i], axis=1)

    df["direction"] = 1

    g = df.groupby(by=["flow_ID"], as_index=True)
    connections = list(g.groups.keys())

    for flowname, grp in g:
        uflows = grp.groupby(by=["IP__src_s"], as_index=True)

        ips = list(uflows.groups.keys())
        l = len(ips)

        if l == 2:
            idx = uflows.groups[ips[1]]
            df.loc[idx, "direction"] = -1

    return df["direction"]


def truncate(vector, param=100):

    size = vector.shape[0]

    if size > param:
        vector = vector[0:param].values

    else:
        vector = np.append(vector.values, np.zeros(param - size))

    return vector


def create_feature(parameters, inp_name, func_params, results=None):

    df1, ty1 = results[inp_name[0]]

    df1.reset_index(drop=True, inplace=True)

    for each_feat in func_params["list"]:

        if "mode" in func_params:
            fname = each_feat.split(":")[0]

        else:

            fname = FE_prefix + each_feat

        print("FEAT\t\n", each_feat)
        spl = each_feat.split(":")
        fields_touse = spl[1].split(",")
        print(spl, fields_touse)

        feat_res = functionlist[spl[0]](*[df1[i] for i in fields_touse])

        print("THE FEATURE IS:")

        print("Nummber of unknown entries", (feat_res == np.nan).sum() / feat_res.size)
        print("Trying to append")
        df1.reset_index(drop=True, inplace=True)
        df1[fname] = feat_res

        print("Append finished")
        print(df1.head())

    return df1, type(df1)


def header_extract_flow(parameters, inp_name, func_params, results=None):

    train = DataHandler(
        path=parameters["data_path"],
        ndf=parameters["ndf_train"],
        fields=func_params["param"],
        count=parameters["packet_count"],
        distributed=parameters["distributed"],
        data_mode=parameters["data_mode"],
        parameters=parameters,
        func_params=func_params,
    ).dflow(mode="flow")

    return train, type(train)


def header_extract(parameters, inp_name, func_params, results=None):

    train = DataHandler(
        path=parameters["data_path"],
        ndf=parameters["ndf_train"],
        fields=func_params["param"],
        count=parameters["packet_count"],
        distributed=parameters["distributed"],
        data_mode=parameters["data_mode"],
        parameters=parameters,
        func_params=func_params,
    ).df()

    return train, type(train)


def impute(parameters, inp_name, func_params, results):
    data, ty = results[inp_name[0]]
    params = func_params["params"]


def clean(parameters, inp_name, func_params, results):
    data, ty = results[inp_name[0]]
    params = func_params["params"]


def filteration(parameters, inp_name, func_params, results):

    data, _ = results[inp_name[2]]
    return data


def custom_column(parameters, inp_name, func_params, results):
    data, ty = results[inp_name[0]]
    return


def debugger(parameters, inp_name, func_params, results):

    df, ty = results[inp_name[0]]
    print(df, ty)
    print("DOne overall", Counter(df["Label"]))

    cols = "bidir"

    count_series = df.groupby([cols, "Label"]).size()
    new_df = count_series.to_frame(name="size").reset_index()

    print(new_df)
    new_df.to_csv("debug.csv", index=False)

    () + 1


def flowbuilder_map(parameters, inp_name, func_params, results):

    data, ty = results[inp_name[0]]
    flowid = func_params["param"]
    for i in flowid:
        if i not in data.columns:
            flowid.remove(i)
            print("Skipping the flow building using {} ".format(i))

    if type(flowid) == list:
        ddf = data.groupby(by=flowid, as_index=False)

        grp = ddf.groups
        return grp, "dictionary"


def flowbuilder(parameters, inp_name, func_params, results):
    swap = {
        "IP__src_s": "IP__dst_s",
        "IP__dst_s": "IP__src_s",
        "sport": "dport",
        "dport": "sport",
    }
    data, ty = results[inp_name[0]]

    flowid = func_params["flowid"]
    flowid = [i.strip() for i in flowid]

    flowtype = func_params.get("type", "")

    for i in flowid:
        if i not in data.columns:
            flowid.remove(i)
            print("Skipping the flow building using {} ".format(i))

    g = data.groupby(flowid, as_index=True)
    device_id = list(g.groups.keys())
    print("The total number of unidirectional flows are", len(device_id))
    print(flowid, g, type(g))

    if flowtype == "bidirectional":

        fid = []
        if "IP__src_s" in flowid:
            fid.extend(["IP__src_s", "IP__dst_s"])
            flowid.remove("IP__src_s")

        if "IP__dst_s" in flowid:
            if "IP__dst_s" not in fid:
                fid.extend(["IP__src_s", "IP__dst_s"])
            flowid.remove("IP__dst_s")

        if "sport" in flowid:
            fid.extend(["sport", "dport"])
            flowid.remove("sport")

        if "dport" in flowid:
            if "dport" not in fid:
                fid.extend(["sport", "dport"])
            flowid.remove("dport")

        fid.extend(flowid)
        flowid = fid.copy()
        data["direction"] = 0
        data["FID"] = np.nan
        data["FID"] = data["FID"].astype(object)

        for j in g.groups.keys():

            if type(j) == "str":
                i = list(j)
            else:
                i = j

            i2 = []
            c = 0
            if "IP__src_s" in flowid:
                i2 = [i[1], i[0]]
                c = 1
            if "sport" in flowid:
                i2 = i2 + [i[3], i[2]]
                c = 3
            if len(i) > c + 1:
                i2 = i2 + list(i)
            i2 = tuple(i2)

            print(i, i2)

            temp = list(g.groups[i])

            data.loc[temp, "direction"] = 1

            data.loc[temp, "FID"] = pd.Series([tuple(i) for j in range(len(temp))])

            if (i2 in device_id) & (i != i2):

                temp = list(g.groups[i2])

                data.loc[temp, "direction"] = -1
                data.loc[temp, "FID"] = pd.Series([tuple(i2) for j in range(len(temp))])

        print("the flowid is::::", flowid)
        ids = [i + "_id" for i in flowid]

        print(data["FID"], data["FID"].nunique())
        data[ids] = pd.DataFrame(data["FID"].tolist(), index=data.index)
        g = data.groupby(by=ids, as_index=True)

        print("The total number of bidirectional flows are", data["FID"].nunique())
        print(data)
        return g, type(g)

    elif (flowtype == "unidirectional") | (flowtype == ""):

        g = data.groupby(by=flowid, as_index=True)
        print(g, type(g))

    if results["debug"]:
        print("Grouped packets using {}".format(flowid))
        print("Total groups are {}".format(len(g.groups.keys())))
    return g, type(g)


def timeslicer(parameters, inp_name, func_params, results):
    df, ty = results[inp_name[0]]
    groups = []
    slice_type = func_params.get("type", "time")
    amount = int(func_params.get("amount", 100))

    if slice_type == "size":
        df_final = pd.DataFrame()
        if "groupby" in str(ty):

            for name, group in df:
                counter = 0

                for i in range(0, group.shape[0], int(amount)):
                    df_sub = group.iloc[i : i + amount, :]
                    n = list(name)
                    n.append(counter)
                    print(n)

                    df_sub.loc[:, "group_temp"] = pd.Series(
                        [tuple(n) for x in range(len(df_sub.index))]
                    )
                    df_final = df_final.append(df_sub)
                    counter += 1
            ddf = df_final.groupby("group_temp")
        else:
            counter = 0
            for i in range(0, df.shape[0], amount):
                df_sub = df.iloc[i : i + amount, :]
                df_sub["group_temp"] = str(counter)
                df_final = df_final.append(df_sub)
                counter += 1

        return ddf, type(ddf)

    elif slice_type == "time":

        if "groupby" in str(ty):

            groups = df.grouper.names
            df = df.obj
            groups.append(pd.Grouper(key="packet__time", freq=func_params["freq"]))
            ddf = df.groupby(groups, as_index=True)
        else:
            ddf = df.groupby(
                pd.Grouper(key="packet__time", freq=func_params["freq"]), as_index=True
            )

        if results["debug"]:
            print("Grouped packets using {}".format(groups))
            print(ddf.grouper.ngroups)

        return ddf, type(ddf)

    else:
        print("Pass a Valid Timeslicer Type: size or time (in milliseconds) ")


def timeslicer2(parameters, inp_name, func_params, results):

    df, ty = results[inp_name[0]]
    print(df, ty)
    time_field = "packet__time"
    window = func_params["window"]
    index_by = "index"
    cur_group = 0
    df_final = pd.DataFrame()
    print(ty)

    indexer = func_params.get("index", "")

    if "groupby" in str(ty):

        for idx, grp in df:
            for index, row in grp.iterrows():
                cur_time = pd.to_datetime(row[time_field])

                end_time = cur_time
                start_time = cur_time - pd.Timedelta(window, "millisecond")
                mask = (grp[time_field] > start_time) & (grp[time_field] <= end_time)
                df_sub = grp.loc[mask]

                t = list(idx)
                t.append(row[index_by])

                if indexer == "packet":

                    t = row[index_by]

                df_sub.loc[:, "group_temp"] = [t] * df_sub.shape[0]

                df_final = pd.concat([df_final, df_sub])

                cur_group += 1

        ddf = df_final.groupby(by="group_temp")
        return ddf, type(ddf)

    for index, row in df.iterrows():
        cur_time = pd.to_datetime(row[time_field])

        end_time = cur_time
        start_time = cur_time - pd.Timedelta(seconds=window)
        mask = (df[time_field] > start_time) & (df[time_field] <= end_time)
        df_sub = df.loc[mask]

        df_sub["group_temp"] = row[index_by]
        df_final = df_final.append(df_sub)

        cur_group += 1
    ddf = df_final.groupby(by="group_temp")

    if results["debug"]:
        print("Creating Packet group for time window")
        print(ddf)
        print("total groups created", cur_group)

    return ddf, "dataframe.groupby.object"


def timeslicer_map(parameters, inp_name, func_params, results):
    df, ty = results[inp_name[0]]
    groups = []
    if "groupby" in ty:
        groups = df.grouper.names
        df = df.obj
    groups.append(pd.Grouper(key="packet time", freq=func_params["freq"]))

    return df.groupby(by=groups).groups, "dictionary"


def maptopacket(parameters, inp_name, func_params, results):

    dictionary, ty = results[inp_name[0]]
    dataframe, ty = results[inp_name[1]]
    field_tomatch = func_params.get("matchon", "bidir")

    ndl = []
    for k1, v1 in dictionary.items():

        d1 = {}

        if type(k1) == "str":
            fnames = [k1]
        else:
            fnames = list(k1)

        ndl.append(v1)
    df_feat = pd.DataFrame(ndl, index=dictionary.keys())
    df_feat = df_feat.fillna(0)

    touse = []
    cols = func_params["features"]

    for i in cols:
        for j in df_feat.columns:
            if i in j:
                touse.append(j)
                dataframe[j] = 0

    features = df_feat[touse]

    for i in dictionary.keys():

        dfshape = dataframe[dataframe[field_tomatch] == i].shape[0]

        for col in features.columns:

            if dfshape == len(df_feat.loc[i, col]):

                dataframe.loc[dataframe[field_tomatch] == i, col] = np.array(
                    df_feat.loc[i, col]
                )

            else:
                print(
                    "Features less than packets in the flow, apending all to each packet"
                )
                dataframe.loc[dataframe[field_tomatch] == i, col] = [
                    np.array(df_feat.loc[i, col])
                ] * (dfshape)

    print(dataframe[col].unique())

    return dataframe, type(dataframe)


def aggregates2(parameters, inp_name, func_params, results):

    df, ty = results[inp_name[0]]
    features = {}
    vsize = func_params.get("vsize", None)
    vectors = func_params.get("vectors", "").split(",")
    vectors = [i.strip() for i in vectors]
    for name, group in df:

        grp = {}

        for each_feat in func_params["list"]:
            spl = each_feat.split(":")

            fields_touse = spl[1].split(",")

            if len(spl) == 3:
                direction = spl[2]
                df_subset = group[group["direction"] == direction][fields_touse]
            else:
                df_subset = group[fields_touse]

            print("Original dataframe is", df_subset.shape)

            if spl[0] in vectors:
                df_subset = df_subset.head(vsize)
                if df_subset.shape[0] < vsize:
                    arr = np.empty((100 - df_subset.shape[0], df_subset.shape[1]))
                    arr[:] = str(np.NaN)
                    df_subset = df_subset.append(
                        pd.DataFrame(arr, columns=df_subset.columns), ignore_index=True
                    )

            res = functionlist[spl[0]](*[df_subset[i.strip()] for i in fields_touse])

            if spl[0] in vectors:
                if len(res) > vsize:
                    res = res[0:vsize]
                else:
                    res = np.append(res, np.zeros(vsize - len(res)))

                print("Shape of features", res.shape)

            if "Label" in fields_touse:
                grp["Label"] = res
            else:
                grp["FE::" + each_feat] = res

        features[name] = grp

    if results["debug"]:
        print("Aggregation Completed")

    return features, "dict"


@ray.remote
def applyFun1(fname, each_feat, tpr):
    print("HERE", fname, each_feat, tpr)
    direction = None
    feat_name = "FE::" + each_feat
    d1 = {}
    spl = each_feat.split(":")

    funs = str(spl[0])
    fields_touse = spl[1].split(",")
    if len(spl) == 3:
        direction = spl[2]

    params = -1
    if len(spl) == 4:
        params = spl[3]

    sys.path.append("/data/ray/pkml/mliot/distributed")

    print("Done till here")
    import functionlist as fl1

    print(fl1)
    fun_cal = fl1.functionlist[funs]
    with open(fname, "rb") as handle:
        cur_dict = pickle.load(handle)

    for grp_name, groups in cur_dict.items():

        if grp_name not in d1:
            d1[grp_name] = {}

        if direction:
            dff = groups[groups["direction"] == direction]
        else:
            dff = groups

        if "packet__time" in dff.columns:
            dff["packet__time"] = pd.to_datetime(dff["packet__time"])

        res = fun_cal(*[dff[i] for i in fields_touse])

        if (params != -1) & isinstance(res, np.ndarray):
            res = truncate(res, param=params)

        d1[grp_name][feat_name] = res

    print("Finished \t", feat_name, tpr)
    print("\n\n\n\n")
    sys.stdout.flush()

    return d1


@ray.remote
def applyFunRemote(fname, each_feat, tpr):

    print("ApplyFunRemote HERE", fname, each_feat, tpr)

    direction = None

    feat_name = "FE::" + each_feat

    d1 = {}
    spl = each_feat.split(":")

    funs = str(spl[0])

    if funs == "flow_label":
        feat_name = "flow_label"

    fields_touse = spl[1].split(",")
    print(spl, fields_touse)

    if len(spl) == 3:
        direction = int(spl[2])

    params = -1
    if len(spl) == 4:
        params = spl[3]
        try:
            direction = int(spl[2])

        except:
            direction == None

    sys.path.append("/data/ray/pkml/mliot/distributed")

    print("Done till here")
    import functionlist as fl1

    print(fl1)
    fun_cal = fl1.functionlist[funs]

    with open(fname, "rb") as handle:
        cur_dict = pickle.load(handle)

    for grp_name, groups in cur_dict.items():

        if grp_name not in d1:
            d1[grp_name] = {}

        if direction:
            dff = groups[groups["direction"] == direction]
        else:
            dff = groups

        if "packet__time" in dff.columns:
            dff["packet__time"] = pd.to_datetime(dff["packet__time"])

        if params == -1:
            res = fun_cal(*[dff[i] for i in fields_touse])
        else:

            res = fun_cal(*[dff[i] for i in fields_touse], params)

        d1[grp_name][feat_name] = res

    print("Finished \t", feat_name, tpr)
    print("\n\n\n\n")
    sys.stdout.flush()

    return d1


def applyFun(funs, ty):
    print(funs)

    if "groupby" in str(ty):

        result = dff.apply(fun_cal)
    else:
        result = functionlist[spl[0]](*[dff[i] for i in fields_touse])
    return name, result


def aggregates(parameters, inp_name, func_params, results):

    df, ty = results[inp_name[0]]
    over_start = time.time()
    sv_fold = parameters["save_directory"] + "temp/"
    print("DELETING files")

    if os.path.exists(sv_fold):
        csv_path = sv_fold + "/*.csv"

        files = glob(csv_path, recursive=True)

        for f in files:
            try:
                os.remove(f)
                print(f)
            except OSError as e:
                print("Error: %s : %s" % (f, e.strerror))
        shutil.rmtree(sv_fold)

    print("DELETING done")

    time.sleep(5)

    os.makedirs(sv_fold)

    mode = parameters["distributed"]
    result_ids = []

    if mode == 1:
        start_ray()

        result_ids = []

    files_created = []
    features = {}
    dict_all = {}

    print("TY", ty)
    if "groupby" in str(ty):

        iter = 0

        num_splits = 10

        per_elem_limit = parameters["agg_per_elem_limit"]

        cur_dict = {}
        count = 0
        iter = 0

        counter = 0
        for i, (grp_name, groups) in enumerate(df):
            if i % 10000 == 0:
                print(i, grp_name, iter, count, per_elem_limit, type(groups))
            csv_path = sv_fold + str(counter) + ".csv"

            cur_dict[grp_name] = groups
            counter += 1
            count += 1
            if count >= per_elem_limit:
                path = sv_fold + str(iter) + ".pickle"
                print("Saving pickle", path)
                with open(path, "wb") as f:
                    pickle.dump(cur_dict, f)
                cur_dict = {}
                count = 0
                iter += 1

        path = sv_fold + str(iter) + ".pickle"
        print("Saving pickle", path)
        iter += 1

        with open(path, "wb") as f:
            pickle.dump(cur_dict, f)
        time.sleep(10)

        result_ids = []

        for i in range(iter):
            fname = sv_fold + str(i) + ".pickle"
            for each_feat in func_params["list"]:

                tpr = (i, each_feat, iter)
                print(i, iter, each_feat, fname, each_feat, grp_name, tpr)
                print(type(fname), type(each_feat), type(tpr))

                result_ids.append(applyFunRemote.remote(fname, each_feat, tpr))

        results = ray.get(result_ids)

        sys.stdout.flush()
        print("\n\n\n\n\n\nFINISHED\n\n\n\n\n")

        new_dict = {}

        for d1 in results:

            for k1, v1 in d1.items():
                if k1 not in new_dict:
                    new_dict[k1] = {}
                new_dict[k1].update(v1)

        features = new_dict

    shutil.rmtree(sv_fold)
    if mode == 1:
        i = 1

    return features, "dict"


def agg2D(parameters, inp_name, func_params, results):

    df1, ty1 = results[inp_name[0]]
    df2, ty2 = results[inp_name[1]]

    features1, _ = results[inp_name[2]]
    features2, _ = results[inp_name[3]]

    print(features1.shape, features2.shape)

    temp = {}
    k1 = df1.groups.keys()
    k2 = df2.groups.keys()

    print(len(k1), len(k2))

    print("Features")
    print(features1)
    print(features2)

    for key1, key2 in zip(k1, k2):
        print(key1, key2)

        temp1 = df1.get_group(key1)
        temp2 = df2.get_group(key2)

        m1 = features1[key1]
        m2 = features2[key2]

        print(m1, m2)
        print(m1.keys(), m2.keys())

        for i in func_params["list2d"]:
            spl = i.split(":")
            fields = i[1].split(",")

            params = None
            if len(spl) == 3:
                params = spl[2]

            res = functionlist[spl[0]](*[temp1[fields], temp2[fields]])

            print(res)

    return 0


def cov(flow1, flow2):

    print(flow1, flow2)

    A = weights_kitsune(flow1["packet__time"])
    B = weights_kitsune(flow2["packet__time"])

    residual = np.sum((A - np.mean(A)) * (B - np.mean(B)))

    return residual


def radius(A, B):

    r = np.sqrt(np.sum(A**2) + np.sum(B**2))
    return r


def pcc(A, B):

    num = cov(A, B)
    den = std(A) * std(B)

    if den != 0:
        corrcoeff = num / den
    else:
        return 0
    return corrcoeff


def magnitude(A, B):

    mag = np.sqrt(np.sum(A**2) + np.sum(B**2))
    return mag


def ploss(tcpseq):

    unique = tcpseq.nunique()

    return len(tcpseq) - unique


def total_loss(tcpseq):

    seq = list(tcpseq)
    start = list(tcpseq)[0]
    c = 0
    for i in range(1, len(tcpseq)):
        if seq[i] != (seq[i - 1] + 1):
            c += 1

    return c


"""def join(parameters,inp_name,func_params,results):
    


    flowid=results[inp_name[0]]
    dictionary,ty=results[inp_name[0]]
    
    

    
    

    print('The length of dictionary is ',len(dictionary))
    df=[]
    for key,value in dictionary.items():
        if(len(df)==0):
            df=pd.DataFrame(value)
        print("-----------------------------{}-------------".format(key))

        try:
            for i in flowid:
                
            df=df.join(pd.DataFrame(value),on='index')

            
        except Exception as e:
            print(e)
        
    print('Final Join Operation gives',df)

    return df,'dataframe'"""


def concatenate(parameters, inp_name, func_params, results):

    if "dictionary" in ty:
        final = {}
        for i in inp_name:
            final.update(results[i])
    elif "dataframe" in ty:

        final = pd.DataFrame()
        print("Original Data Shape", data.shape)
        print("Things to append: ")
        for i in inp_name[1:]:
            final.append(results[i])

            print(results[i].shape, [i for i in results[i].columns if "FE::" in i])

    return final, type(final)


def update_tforms(parameters, tform_type, tform_path):

    sv_path = parameters["save_path"]
    to_append = [tform_type, tform_path]
    g_data = load_dict(sv_path)

    if "tforms" not in g_data:
        g_data["tforms"] = [to_append]
    else:
        g_data["tforms"].append(to_append)

    save_dict(g_data, sv_path)
    return 1


def feature_elim(parameters, inp_name, func_params, results):
    data, ty1 = results[inp_name[0]]
    tem_data = data.copy()
    tem_data = df_transform(tem_data, mode=1)
    print(data, func_params)
    if func_params["params"]["technique"] == "RFECV":
        model = functionlist[func_params["params"]["model"]]()

        rfe = RFECV(estimator=model, n_jobs=-1)
        print(rfe)

        y = tem_data.pop("Label").to_numpy()

        fe = [i for i in tem_data.columns if FE_prefix in i]
        orig_list = fe
        X = tem_data[fe].to_numpy()
        print("FItting", type(X))

        rfe = rfe.fit(X, y)
        print(X, y)
        print(X.shape, y.shape)
        selected = rfe.support_

        to_sel = [i2 for i1, i2 in zip(selected, orig_list) if i1]
        to_sel.append("Label")
        to_sel.append("Label1")

        print(to_sel)

        data, ty1 = results[inp_name[0]]

        new_data = data[to_sel]

        update_tforms(parameters, "column_keep", to_sel)

        return new_data, type(new_data)
    elif func_params["params"]["technique"] == "brute":
        dfi = pd.read_csv("imp.csv")
        lst = list(dfi.columns)
        newlst = []
        for i in lst:
            if FE_prefix in i:
                newlst.append(i)
            elif FE_prefix_old in i:
                newlst.append(FE_prefix + i)
        to_sel = newlst[-50:]
        to_sel.append("Label")
        to_sel.append("Label1")
        print(to_sel, data.columns)
        data, ty1 = results[inp_name[0]]

        new_data = data[to_sel]

        update_tforms(parameters, "column_keep", to_sel)
        return new_data, type(new_data)

    else:
        () + 1
        print(model)


def keep_FE(parameters, inp_name, func_params, results):
    data, ty1 = results[inp_name[0]]

    fe = [i for i in data.columns if "FE::" or "Label" in i]

    df1 = data[fe]
    return df1, type(df1)


def expand_dftolist(df_feat, mode=0):

    dfs = []
    start_ray()

    initial = []

    old_cols = []
    new_cols = []
    to_expand = []
    print(df_feat.shape)

    gg = min(1000, df_feat.shape[0])

    dfi = df_transform(df_feat.sample(gg), mode=0)

    for cl1 in dfi.columns:

        df_small = dfi[cl1]
        if FE_prefix_old not in cl1:
            old_cols.append(cl1)
            new_cols.append(cl1)

        else:
            n_ext = FE_prefix + cl1

            df_new = pd.DataFrame(df_small.to_list(), index=df_small.index)

            print(cl1, type(dfi), df_new.shape)
            if df_new.shape[1] == 1:
                old_cols.append(cl1)
                new_cols.append(n_ext + "_" + str(0))
            else:
                to_expand.append(cl1)
    print(old_cols)
    print(new_cols)
    df_1 = df_feat[old_cols]
    df_1.columns = new_cols

    if len(to_expand) == 0:

        print(df_1.columns)
        print(df_1.shape)

        return df_1
    else:

        df2 = df_feat[to_expand]

        lencol = len(list(df2.columns))

        if lencol <= 10:
            dist = 0
        else:
            dist = 1

        if dist == 1:

            df2 = df_transform(df2)
            df_ref = ray.put(df2)

        result_ids = []
        results = []

        print(df2.columns, df2.shape)
        params = {}

        for index, cl1 in enumerate(df2.columns):
            print(index, cl1, len(list(df2.columns)), dist)

            F1 = Rem.remote(params)
            if dist == 1:
                result_ids.append(F1.par_merge.remote(df_ref, cl1, index))
            else:
                results.append(par_merge(df_feat, cl1, index))

        print("WAiTING", dist)

        if dist == 1:
            results = ray.get(result_ids)
            del df_ref

        print("Concatting")
        start_ray()
        df_2 = pd1.concat(results, axis=1)

        df_feat = pd1.concat([df_1, df_2], axis=1)

        print(df_feat.head())
        print(df_feat.shape)

        return df_feat


def expand_dftolist1(df_feat, mode=0):

    dfs = []
    start_ray()

    lencol = len(list(df_feat.columns))

    if lencol <= 10:
        dist = 0
    else:
        dist = 1

    if dist == 1:

        df_ref = ray.put(df_feat)

    result_ids = []
    results = []

    print(df_feat.columns, df_feat.shape)
    params = {}

    for index, cl1 in enumerate(df_feat.columns):
        print(index, cl1, len(list(df_feat.columns)), dist)

        F1 = Rem.remote(params)
        if dist == 1:
            result_ids.append(F1.par_merge.remote(df_ref, cl1, index))
        else:
            results.append(par_merge(df_feat, cl1, index))

    print("WAiTING", dist)

    if dist == 1:
        results = ray.get(result_ids)
        del df_ref

    print("Concatting")

    df_feat = pd1.concat(results, axis=1)

    print(df_feat.head())
    print(df_feat.shape)

    return df_feat


def join2(parameters, inp_name, func_params, results):

    df1, ty1 = results[inp_name[0]]

    fkey, fvalue = next(iter((df1.items())))

    ndl = []

    fields_tomatch = func_params["matchon"]

    for k1, v1 in df1.items():
        d1 = {}
        fnames = [k1]

        dictionary = dict(zip(fields_tomatch, fnames))

        v1.update(dictionary)

        ndl.append(v1)

    df_feat = pd.DataFrame(ndl)

    df_feat = df_feat.fillna(0)

    how = func_params["how"]
    if (how == "none") | (how == None):

        df_feat.rename(columns={"flow_label": "Label"}, inplace=True)

        print("SAVING\t", df_feat.shape)

        print(df_feat.head(5), df_feat.columns)

        df_feat = expand_dftolist(df_feat, mode=1)

        print("SAVING\t", df_feat.shape)
        print(df_feat.head())

        time.sleep(2)

        return df_feat, type(df_feat)

    df2, ty2 = results[inp_name[1]]

    partials = func_params.get("partialmatch", None)
    if partials:

        print(df2.head())
        print(df2.columns)
        print(df2.shape)
        df2["packet__time"] = pd.to_datetime(df2["packet__time"])

        full_match = []
        partial_match = []
        freqs = []
        print(fkey)

        for temp, field in zip(fkey, fields_tomatch):
            if field in partials:
                psp = pd.Timestamp.now()
                psp1 = psp + temp.freq
                diff = (psp1 - psp).total_seconds()

                partial_match.append((field, diff))

            else:
                full_match.append(field)

        print(full_match, partial_match)
        parts = [a_tuple[0] for a_tuple in partial_match]
        print(parts)

    if how == "asof_pack":
        print(df_feat.head())

        print(df_feat.shape)

        print(df_feat.columns)
        if "packet__time" in df_feat.columns:
            df_feat.sort_values(by=["packet__time"], inplace=True)
            df_feat["dummy_time"] = df_feat["packet__time"]
        df2.sort_values(by=["packet__time"], inplace=True)

        df_final = pd.merge_asof(
            df2, df_feat, on=parts, by=full_match, direction="backward"
        )
        print(df_final.head())
        print(df_final.shape)

        return df_final, type(df_final)

    elif how == "asof_flow":
        df_feat.sort_values(by=["packet__time"], inplace=True)
        df2.sort_values(by=["packet__time"], inplace=True)

        df_feat["dummy_time"] = df_feat["packet__time"]

        df_final = pd.merge_asof(
            df2, df_feat, on=parts, by=full_match, direction="backward"
        )
        print(df_final.head())
        print(df_final.shape)
        () + 1

        return df_final

    else:
        () + 1

    return df_final, type(df_final)


def join(parameters, inp_name, func_params, results):

    sys.stdout.flush()
    print("\n\n\n\n\n\n,Joining", inp_name)
    df1, ty1 = results[inp_name[0]]

    groups = df1.keys()
    features = df1.values()
    df_feat = pd.DataFrame(data=features, index=groups)

    print(df_feat.head())

    print(df_feat.shape)

    if len(inp_name) == 2:
        print("Packet based Feature Engineering")
        df2, ty2 = results[inp_name[1]]
    else:
        print("Flow based Feature Engineering")

        new = pd.DataFrame(df1.values(), index=df1.keys())

        print("Output of Aggregates2 in dataframe", new)

        cols = new.select_dtypes(exclude=[int, float]).columns
        print("Columns selected", cols)
        for i in cols:

            series = new.pop(i)
            print("Vectorizing Feature for flows", i)

            v = series.apply(lambda x: x.tolist()).reset_index(drop=True)

            a = pd.DataFrame(
                v.tolist(),
                columns=[i + "_" + str(j) for j in range(0, len(series[0]))],
                index=new.index,
            )
            print("Convert to {} Flow features ".format(a.shape))

            new = pd.merge(new, a, left_index=True, right_index=True)

        print(new.shape)

        if results["debug"]:

            print("DataFrame created with new features of shape {}".format(new.shape))
            print(
                "Flow Label distributioon is as follows \n", new["Label"].value_counts()
            )
            print(new.to_numpy()[0:5])
        new.fillna(0, inplace=True)
        return new, type(new)

    for k, v in df1.items():

        t = v.reset_index(drop=True)

        if type(t) == pd.DataFrame:
            t = v[None]
        if t.shape[0] != df2.shape[0]:
            on = func_params["on"]
            print(df2.columns, on, t)
            print(type(df2))
            df2 = pd.merge(
                df2,
                pd.DataFrame({k + "_1": t}),
                how="left",
                left_on=on,
                right_index=True,
            )
        else:
            print("Inside Else Statement")
            df2 = pd.merge(
                df2,
                pd.DataFrame({k + "_1": t}),
                how="left",
                left_on="index",
                right_index=True,
            )

    print("Flow based features concatenated to individual packets ", df2.head())
    df2 = df2.fillna(0)
    return df2, type(df2)


def header_group(df):
    df["sport"] = df.apply(
        lambda x: x["TCP__sport"] if "TCP" in x["packet__layers"] else x["UDP__sport"],
        axis=0,
    )
    df["dport"] = df.apply(
        lambda x: x["TCP__dport"] if "TCP" in x["packet layers"] else x["UDP__dport"],
        axis=0,
    )
    return df, type(df)


def combine_data(parameters, inp_name, func_params, results):
    pass


def transforms(parameters, inp_name, func_params, results):

    data, ty = results[inp_name[0]]
    print(type(data))

    data_r = data.copy()
    method = None
    if "params" not in func_params.keys():
        func_params["params"] = {}

    else:
        try:
            method = func_params["params"]["method"]
        except:
            pass

    trf = functionlist[func_params["transform_type"]](**func_params["params"])

    print("Applying Transform", trf)

    if ty == pd.DataFrame or pd1.DataFrame:

        label = data["Label"].to_numpy().reshape(-1, 1)
        label1 = data["Label1"].to_numpy().reshape(-1, 1)

        keep_orig_cols = 0

        if "applylist" in func_params:

            aplist = func_params["applylist"]
            print(aplist)
            keep_orig_cols = 1
            fe = []
            for i in aplist:
                for j in data.columns:
                    if i in j:
                        fe.append(j)

            fe_keepsame = list(set(data.columns) - set(fe))

        else:
            fe = [i for i in data.columns if FE_prefix in i]
            fe_keepsame = []

        print("Here", data.shape)
        data1 = data[fe]

        if type(data1) == pd1.DataFrame:
            data1 = data1._to_pandas()

        data = data1.to_numpy()
        print("FE\t", fe)
        print("FE Keep Same", fe_keepsame)
        print(data.shape)

    else:
        raise ("Please pass a Pandas DataFrame for Transform")
        data = data[:, 0:-1]
        label = data[:, -1]

        () + 1

    print("Data before transform", type(data), data.shape, len(data))

    if data.shape[1] == 0:
        cols = list(set(data_r.columns) - set(["Label", "Label1", "Unnamed: 0"]))
        data = data_r[cols].to_numpy()
        print("The Kitsune features are", data.shape)

    trf = trf.fit(data)

    path = parameters["save_directory"]

    rd = my_random_string()

    path = (
        parameters["save_directory"]
        + "/"
        + str(rd)
        + trf.__class__.__name__
        + "_transform.pickle"
    )

    with open(path, "wb") as f:
        pickle.dump(trf, f)

    update_tforms(parameters, "picklemodel", (path, fe))

    data1 = trf.transform(data)

    if method:
        print("The feature mapping is", data1)
        print("returning feature clustering for kitsune")
        return data1, type(data1)

    print(data.shape, data1.shape)

    if keep_orig_cols:
        names = fe
    else:
        names = [
            FE_prefix + my_random_string() + "::" + str(i)
            for i in range(data1.shape[1])
        ]

    df_new = pd.DataFrame(data1, columns=names)

    if len(fe_keepsame) > 0:
        df_r = data_r[fe_keepsame]
        print("Append KeepSame")
        df_new = pd1.concat([df_new, df_r], axis=1)

    df_new["Label"] = label
    df_new["Label1"] = label1

    return df_new, type(df_new)


def applytransform(v1, data):
    """
    Parameters
    ----------
    arg1: String
    The path of the stored model to be applied on the data

    arg2: DataFrame
    The pandas DataFrame on which the transform need to be applied


    Returns
    -----------
    Pandas DataFrame
         New transformed features and True Label in the last column
    """

    path, fe = v1

    trf = load_dict(path)

    try:
        if trf.method == "Incremental":
            return data
    except:
        pass

    label = data["Label"].to_numpy().reshape(-1, 1)

    fe_keepsame = list(set(data.columns) - set(fe))
    df_keep = data[fe_keepsame]

    data = data[fe].to_numpy()

    data = trf.transform(data)

    names = [FE_prefix + my_random_string() + str(i) for i in range(data.shape[1])]

    data = pd.DataFrame(data, columns=names)

    if len(fe_keepsame) > 0:

        print("Append KeepSame")
        data = pd1.concat([data, df_keep], axis=1)

    data["Label"] = label

    return data


def model(parameters, inp_name, func_params, results):

    print("Initializing Model--->", func_params["model_type"])
    if "params" not in func_params.keys():
        func_params["params"] = {}

    if inp_name[0] == "fmap":
        func_params["params"]["fmap"] = results["fmap"][0]

    if type(func_params["model_type"]) == str:
        clf = functionlist[func_params["model_type"]](**func_params["params"])
    else:
        clf = func_params["model_type"](**func_params["params"])

    print("Using Classifer {} for training ".format(clf))

    return clf, func_params["model_type"]


def rename_cols(df):
    map1 = {}
    for i in df.columns:
        if FE_prefix in i:
            i1 = i
        elif FE_prefix_old in i:
            i1 = FE_prefix + i
        else:
            i1 = i

        map1[i] = i1
    print(map1)

    df1 = df.rename(columns=map1)
    return df1


def train(parameters, inp_name, func_params, results):

    model, typ = results[inp_name[0]]
    data, ty = results[inp_name[1]]

    del results

    gc.collect()

    if ty == pd.DataFrame or ty == pd1.DataFrame:
        if "flow_ID" in data.columns:
            og_data = data[["Label", "Label1", "flow_ID"]]
        else:
            og_data = data[["Label", "Label1"]]

        print(data.columns)
        print("HERE")

        y = data["Label"].to_numpy()

        print("H12", data.columns)

        fe = [i for i in data.columns if FE_prefix in str(i)]

        if "FE_final::FE::flow_duration:packet__time:0_0" in fe:
            fe.remove("FE_final::FE::flow_duration:packet__time:0_0")

        print("Selected Features are \n", fe)

        if len(fe) == 0:
            print(
                "Please add Feature Prefix, using all columns for training except label and label1 "
            )
            cols = list(set(data.columns) - set(["Label", "Label1", "Unnamed: 0"]))
            data = data[cols]
        else:
            data = data[fe]

            data = data.replace({"-": 0})
            data = data.fillna(0)

    elif ty == dict:
        print("Dict")
        og_data = data["label"][["Label", "Label1"]]
        print(og_data)
        y = og_data["Label"]
        print(y)
        data = data["numpy"]
        print(data)

    else:
        print(type(data), data.columns, data.shape)

        y = data[:, -1]
        data = data[:, 0:-1]
        () + 1

    print("Training on dataset of shape  ", data.shape)
    print("Data Distribution", Counter(y))

    register_ray()

    print(type(model), type(data))

    if "flaml" in str(type(model)):
        data = data.to_numpy()

        model.fit(data, y)
        ypred = model.predict(data)

    else:

        print("Training")
        print("Training", Counter(y), type(data), type(y))

        with joblib.parallel_backend("ray", n_jobs=-1):
            model.fit(data, y)
            print("Successfully Trained the Model")
            ypred = model.predict(data)

    og_data["y_predict"] = ypred

    res = metrics(y, ypred)

    print(res)
    print(og_data)
    sv_path = parameters["res_path"]
    res["csv_path"] = sv_path + ".csv"
    del data

    og_data.to_csv(sv_path + ".csv", index=False)

    print(sv_path)

    res["y_count"] = np.array(np.unique(y, return_counts=True)).T.tolist()
    res["ypred_count"] = np.array(np.unique(ypred, return_counts=True)).T.tolist()

    print(res)

    with open(sv_path, "w") as fp:
        json.dump(res, fp)
    print("Machine Learning Model on training Data \n ", res)

    path = save(parameters, model, inp_name)
    print("Successfully Stored the Model")

    return model, path


def test(parameters, inp_name, func_params, results):

    g_data = load_dict(parameters["save_path"])
    print(g_data)

    data1, ty = results[inp_name[0]]
    print("test function called", ty)
    if "flow_ID" in data1.columns:
        og_data = data1[["Label", "Label1", "flow_ID"]]
    else:
        og_data = data1[["Label", "Label1"]]

    if ty == pd.DataFrame or pd1.DataFrame:
        print(data1.columns)

        if "tforms" in g_data:
            print(g_data)
            all_tforms = g_data["tforms"]
            print("Tranforms to be applied in sequence are as follows", all_tforms)

            for (k1, v1) in all_tforms:

                if k1 == "column_keep":
                    data1 = data1[v1]

                elif k1 == "picklemodel":

                    data1 = applytransform(v1, data1)

                else:
                    () + 1

        y = data1.pop("Label").to_numpy()

        fe = [i for i in data1.columns if FE_prefix in i]
        print("Converting to numpy")
        d_small = data1[fe]

        data = d_small
        data = data.replace({"-": 0})
        data = data.fillna(0)

        print("conversion done")

    else:
        y = data_old[:, -1]
        data = data_old[:, 0:-1]
        () + 1

    print("Testing on dataset of shape  ", data.shape)

    shp = np.array(data.shape)
    model_path = g_data["model_path"]
    print(model_path)

    loaded_model = pickle.load(open(model_path, "rb"))

    print("Successfully Loaded the Model")
    print(loaded_model)

    print("SHP")
    if data.shape[0] == 0:
        ypred = y
    else:

        if "flaml" in str(type(loaded_model)):
            data = data.to_numpy()

        ypred = loaded_model.predict(data)

    og_data["y_predict"] = ypred

    print("saved results")

    d1 = {}
    d1["y"] = y
    d1["ypred"] = ypred
    d1["shp"] = shp
    d1["dataframe"] = og_data

    return d1, type(d1)


def makedir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)


def size_vector(v1):
    return v1.to_numpy()


def rtt(*vector):

    df = pd.DataFrame()
    for i in vector:
        df = pd.concat([df, i], axis=1)

    print(df)

    start = df.loc[df["TCP__flags"] == 2, "packet__time"][0]

    end = df.loc[df["TCP__flags"] == 16, "packet__time"][0]

    if end > start:
        return (end - start).total_seconds()
    else:
        return (df["packet__time"].tolist()[-1] - start).total_seconds()


def DFT(vector, params=None):

    if params != None:
        freq = fft(vector, n=params)
    else:
        freq = fft(vector, n=10)

    freq = np.angle(freq)

    return freq


def IAT(series, params=None):

    s1 = series.sort_values(ascending=True)
    series = s1.diff().fillna(pd.Timedelta(seconds=0)).dt.total_seconds()

    if params != None:
        series = truncate(series, int(params))

    return series


def dIAT(time, params=None):

    series = IAT(time)

    diat = (series.diff()).fillna(0)

    if params != None:
        diat = truncate(diat, int(params))

    return diat


def ddIAT(time):

    series = dIAT(time)
    return (series.diff()).fillna(0)


def novelty(vector):
    global laste
    temp = cardinality(vector) - laste
    laste = cardinality(vector)
    return temp


def isTCP(vector):
    temp = vector.apply(lambda x: int("TCP" in x))
    return temp.to_numpy()


def bidir(*vector):
    df = pd.DataFrame()
    for i in vector:

        df = pd.concat([df, i], axis=1)
    print(df)
    df = df.fillna(0)

    for i in df.columns:
        df[i] = df[i].astype(str)

    df["concat_col"] = df.apply(lambda row: "-".join(sorted(row.tolist())), axis=1)
    return df["concat_col"]


def isHTTP(vector):

    return vector.apply(lambda x: int("TCP" in x)).to_numpy()


def isUDP(vector):
    return vector.apply(lambda x: int("TCP" in x)).to_numpy()


def isOTHER(vector):

    return ((isTCP(vector) + isHTTP(vector) + isUDP(vector)) == 0).astype(int)


def duration(time):
    return (time.max() - time.min()).total_seconds()


def quantile(vector, q=[0.25, 0.5, 0.75]):

    return np.array(np.quantile(vector, q=q))


def packet_rate(size, time):
    return len(size) / (duration(time) + 0.01)


def byte_rate(size, time):
    return sum(size) / (duration(time) + 0.01)


def index(vector):
    size = vector.shape[0]

    return np.arange(size)


def bin_index(time):
    def bins(x):
        if x < 0.001:
            return 1
        elif (x < 0.5) & (x > 0.001):
            return 2
        elif x > 0.05:
            return 3
        else:
            return 4

    iat = IAT(time)

    print(iat)

    temp = iat.apply(lambda x: bins(x))
    return temp.to_numpy()


def protocols(layers):
    print(layers)
    return layers.apply(lambda x: len(x)).to_numpy()


def mean(values):

    resd = pd.to_numeric(values, errors="coerce")
    return resd.mean()


def weights_kitsune(time, params=3000):

    lamda = -(time.max() - time.min()).total_seconds()

    s = time.max()
    time = time.apply(lambda x: (s - x).total_seconds())
    time = time * lamda

    time = time.apply(np.exp)
    return time.to_numpy()


def bandwidth(size, time):

    range_time = time.max() - time.min()
    diff = range_time.total_seconds()
    return size.sum() / (diff + 0.01)


def cardinality(vector):
    nq = np.unique(vector)
    return nq.shape[0]


def norm100(values):

    return values.max() / 100.0


def median(values):
    resd = pd.to_numeric(values, errors="coerce")

    return resd.median()


def entropy2(values):
    resd = pd.to_numeric(values, errors="coerce")
    vals = resd.to_numpy()

    return entropy(vals, base=2)


def Min(values):
    return np.min(values)


def Max(values):
    return np.max(values)


def std(values):
    resd = pd.to_numeric(values, errors="coerce")

    return resd.std()


def var(values):
    resd = pd.to_numeric(values, errors="coerce")

    return resd.var()


def coeffofvar(values):
    return std(values) / (mean(values) + 0.01)


def cqv(values):
    q3 = np.quantile(values, 0.75)
    q1 = np.quantile(values, 0.25)

    numer = q3 - q1
    denom = q3 + q1

    return numer / denom


def rateofchange(values):
    return np.unique(values).shape[0] / values.shape[0]


def flows(src, dst):
    df = pd.DataFrame({0: src, 1: dst})
    nunique = len(df.groupby(by=[0, 1]).groups.keys())
    return nunique


def flow_label(vector):

    unq = np.unique(vector).tolist()

    vv = "-".join(unq)
    return vv


def sport(v1, v2):
    temp = []
    for i1, i2 in zip(v1.tolist(), v2.tolist()):
        if i1 != -1:
            temp.append(i1)
        else:
            temp.append(i2)
    return np.array(temp)


def dport(v1, v2):
    temp = []
    for i1, i2 in zip(v1.tolist(), v2.tolist()):
        if i1 != -1:
            temp.append(i1)
        else:
            temp.append(i2)
    return np.array(temp)


def trim(vector, param=100, n=2):

    print(vector)
    param = int(param)
    print(vector.shape[0], n)

    if vector.shape[0] < n:

        r = n - vector.shape[0]
        temp = pd.Series(["[0]"] * r)
        vector = pd.concat([vector, temp], ignore_index=True)

    else:
        vector = vector.iloc[0:n]

    vector = vector.apply(lambda x: json.loads(x))
    vector.apply(lambda x: print(len(x)))

    vector = vector.apply(lambda x: list("".join([bin(i)[2:] for i in x])))
    vector = vector.apply(lambda x: [int(i) for i in x])

    vector = vector.apply(
        lambda x: x[0:param] if len(x) > param else x + [0] * (param - len(x))
    )

    vector = list(vector.values)
    vector = np.array(list(itertools.chain(*vector)))
    print(vector)

    return vector


def last_time(vector):

    return vector.max()


def Bin(vector, q=[0, 0.25, 0.5, 0.75, 1], params=7):

    if type(vector) == np.datetime64:
        vector = IAT(vector)
        r = pd.qcut(vector, q, labels=[1, 2, 3, 4])

    else:

        bins, _ = np.unique(vector.to_numpy(), return_counts=True)
        r = pd.cut(vector, bins=bins[0:params], labels=range(1, len(bins[0:params])))

    return r.to_numpy()


def select(vector, params=None):

    if params != None:
        vector = truncate(vector, int(params))

    if isinstance(vector, np.ndarray):
        return vector
    else:
        return vector.to_numpy()


def flow_select(vector, params=None):

    unique = [0]

    unique = np.unique(vector)
    print(len(unique))

    return unique[0]


def protocol(layers):
    l = set(["TCP", "UDP", "ARP", "ICMP", "-1"])
    temp = layers.apply(lambda x: ("TCP" if "TCP" in x else "UDP"))


def nprotocols(vector):
    v = vector.apply(lambda x: len(x.split(",")))
    return v


def Sum(vector):

    return vector.sum()


def npackets(vector):
    return vector.shape[0]


def tcpsyns(vector):

    print(vector)

    return (vector == 2).sum()


def tcpacks(vector):

    return (vector == 16).sum()


def meanflow(*vectors):

    temp = pd.DataFrame()

    for i in vectors:
        temp = pd.concat([temp, i], axis=1)
    ids = temp.columns
    temp = temp.groupby(ids)

    durations = temp.apply(
        lambda x: (x["packet_-time"].max() - x["packet__time"].min()).total_seconds()
    )
    print(durations.sum())

    return durations.sum()


def tcpsynacks(vector):

    ss = [2, 16]

    vector = vector.tolist()

    res = len([ss for idx in range(len(vector)) if vector[idx : idx + len(ss)] == ss])

    return res


def flagtype(vector):
    d = {"S": 2, "SA": 1, "A": 16, "FA": 3, "PA": 4, "R": 5, "RA": 6, "FPA": 7}
    return vector.map(d, na_action="ignore").to_numpy()


def flow_duration(vector):
    return (vector.max() - vector.min()).total_seconds()


def getGaussianGram(Xrow, Xcol, sigma, goFast=1):

    if goFast == 1:
        A1 = np.expand_dims(np.power(np.linalg.norm(Xrow, axis=1), 2), axis=1)
        A2 = -2 * np.matmul(Xrow, np.transpose(Xcol))
        B = np.power(np.linalg.norm(Xcol, axis=1), 2)
        K = np.add(np.add(A1, A2), np.transpose(B))
        K = np.exp(-K * 1 / sigma**2)

    else:
        Dist = pairwise_distances(Xrow, Y=Xcol, metric="euclidean")
        K = np.exp(-np.power(Dist, 2) * 1 / sigma**2)

    return K


def metrics(true, pred, pred_probab=None):
    a = [true, pred]

    results = {
        "accuracy": -1,
        "F1": -1,
        "Precision": -1,
        "AUC": -1,
        "status": "",
        "TPR": -1,
        "FPR": -1,
        "sensitivity": -1,
    }

    if ((true == 0).sum()) == len(true):
        print(
            "Only Normal Traffic used for training Classifier. Using Reconstruciton Metrics"
        )

        results = {"MSE": -1, "MAE": -1}

    try:
        results["Accuracy"] = accuracy_score(*a)
    except Exception as e:
        print(e)
        results["Accuracy"] = -1.00

    try:
        results["F1"] = f1_score(*a)
    except:
        results["F1"] = -1.00

    try:
        results["Precision"] = precision_score(*a)
    except:
        results["Precision"] = -1.00

    try:
        results["Recall"] = recall_score(*a)
    except:
        results["Recall"] = -1.00

    try:
        results["AUC"] = roc_auc_score(*a)
    except:
        results["AUC"] = -1.00

    try:
        results["BA"] = balanced_accuracy_score(*a)
    except:
        results["BA"] = -1.00

    try:
        results["confuson_matrix"] = confusion_matrix(*a).tolist()
    except:
        results["confuson_matrix"] = -1.00

    results["status"] = "successful"

    return results


def wireshark_features(parameters, inp_name, func_params, results=None):

    count = parameters["packet_count"]

    train = DataHandler(
        path=parameters["data_path"],
        ndf=parameters["ndf_train"],
        fields=[],
        count=parameters["packet_count"],
        distributed=parameters["distributed"],
        data_mode=parameters["data_mode"],
        parameters=parameters,
        func_params=func_params,
    ).df(mode="pdml")

    print(train)

    return train, type(train)


def nprint_features(parameters, inp_name, func_params, results=None):

    count = parameters["packet_count"]

    train = DataHandler(
        path=parameters["data_path"],
        ndf=parameters["ndf_train"],
        fields=[],
        count=parameters["packet_count"],
        distributed=parameters["distributed"],
        data_mode=parameters["data_mode"],
        parameters=parameters,
        func_params=func_params,
    ).df(mode="nprint")

    train["index"] = train.index

    if results["debug"]:
        print("Extracted Packet Headers")
        print(train.head())
        a = (train["Label"] == 1).sum()
        n = train.shape[0] - a
        print(
            "Data consists of {} Normal packets and {} Anomalous packets".format(n, a)
        )

    return train, type(train)


def features_radar(parameters, inp_name, func_params, results=None):

    r = "".join(random.choices(ascii_letters, ascii_uppercase, string.digits, k=10))
    os.makedirs(parameters["data_path"] + "/features_radar/" + r, exist_ok=True)
    path = DataHandler(path=parameters["data_path"], count=parameters["count"]).files
    for i in path:

        os.system(
            "java --class-path /data/Radar/bin /data/Radar/src/Feature_Extractor.java "
            + path
        )


@ray.remote
def read_each(file):
    df = pd.read_csv(file)
    df["packet time"] = pd.to_datetime(df["packet time"])
    return df


@ray.remote
def split_pcap(act_command, pcap_split_path, file_label):
    os.system(act_command)
    all_inds = glob.glob(pcap_split_path + "out*.pcap")
    return all_inds


def read_each_pcap_single(file):
    filename = file[0]
    label = file[1]
    count = file[2]
    fields = file[3]
    mapper = file[4]

    csv_sv_path = file[5]
    if os.path.exists(csv_sv_path):
        print("Already Exist", csv_sv_path)

        return csv_sv_path

    data = []
    cap = pyshark.FileCapture(filename, keep_packets=False)
    cur_count = 0
    for packet in cap:

        temp = {}
        temp["Label"] = label

        for i in fields:
            try:
                to_execute = mapper[i]
                temp[i] = eval(to_execute)

            except Exception as e:
                temp[i] = -1
        temp["packet time"] = str(datetime.fromtimestamp((float(temp["packet time"]))))
        data.append(temp)

        cur_count += 1
        if cur_count > count and count != 0:
            break
        if len(data) % 10000 == 0:
            print(len(data), filename)
    cap.close()

    print("SAVING START", csv_sv_path)
    pd.DataFrame(data).to_csv(csv_sv_path, index=False)
    print("SAVING", csv_sv_path)

    return csv_sv_path


@ray.remote
def read_each_pcap(file):
    filename = file[0]
    label = file[1]
    count = file[2]
    fields = file[3]
    mapper = file[4]

    csv_sv_path = file[5]
    if os.path.exists(csv_sv_path):
        print("Already Exist", csv_sv_path)

        return csv_sv_path

    data = []
    cap = pyshark.FileCapture(filename, keep_packets=False)
    cur_count = 0
    for packet in cap:

        temp = {}
        temp["Label"] = label

        for i in fields:
            try:
                to_execute = mapper[i]
                temp[i] = eval(to_execute)

            except Exception as e:
                temp[i] = -1
        temp["packet time"] = str(datetime.fromtimestamp((float(temp["packet time"]))))
        data.append(temp)

        cur_count += 1
        if cur_count > count and count != 0:
            break
        if len(data) % 10000 == 0:
            print(len(data), filename)
    cap.close()

    print("SAVING START", csv_sv_path)
    pd.DataFrame(data).to_csv(csv_sv_path, index=False)
    print("SAVING", csv_sv_path)

    return csv_sv_path


class DataHandler:
    def __init__(
        self,
        path,
        ndf,
        fields,
        count,
        distributed,
        data_mode,
        parameters,
        func_params,
        tuple=None,
    ):

        self.path = path
        self.fields = fields
        self.distributed = distributed
        self.type = re.split("\.", path)[-1]
        self.data = []
        self.mapper = mapper
        self.ndf = ndf
        self.count = count
        self.files = []
        self.fcount = {}
        self.tuple = tuple
        self.parameters = parameters
        self.func_params = func_params
        self.index = 0
        self.data_mode = data_mode
        self.fmapper = {}

        print(self.path, os.path.isdir(self.path))

        if os.path.isdir(self.path):
            print("Finding Files in Location ", self.path)
            print(self.path)

            print(self.ndf, self.ndf.shape)
            if self.ndf.shape[0] > 1:
                () + 1

            r1 = self.parameters["ndf_train_row"]
            print(r1)
            normal = 0
            attack = 0

            cur_No = r1["No"]
            cur_label = r1["Label"]
            if not cur_label == "Normal":

                attack += 1
            else:
                normal += 1
            cur_folder = self.path + self.data_mode + "/" + str(cur_No)
            print(cur_folder)

            if r1["Datatype"] == "bidir":

                csv_files = glob(cur_folder + "/*.csv")

                df = pd.DataFrame()
                for i in csv_files:
                    data = pd.read_csv(i)
                    df = pd.concat([df, data], ignore_index=True)
                df["Label"] = r1["Label"]
                print(df, "HERERERE")
                self.label_df = df
            else:

                pcap_list = glob(cur_folder + "/*.pcap")
                for ind_cap in pcap_list:
                    self.files.extend([(ind_cap, cur_label)])
                    self.fmapper[ind_cap] = cur_No
            self.fcount = {"Attacks": attack, "Normal": normal}
            print("Files Found ", self.files)
        # ()+1

    def parser(self, packet, label="Normal"):

        temp = {}
        temp["Label"] = label
        for i in self.fields:
            try:
                temp[i] = eval(self.mapper[i])

            except Exception as e:

                temp[i] = -1
        temp["packet time"] = str(datetime.fromtimestamp((float(temp["packet time"]))))

        self.data.append(temp)

    def listdir(self):

        normal = 0
        attack = 0
        folders = os.listdir(self.path)

        for f in folders:
            lpath = self.path + "/" + f

            if lpath.endswith(".pcap"):
                self.files.extend([(lpath, "Normal")])
                normal += 1

            elif (f == "Attacks") | (f == "Anomalous"):

                attacks = os.listdir(lpath)
                for j in attacks:
                    fpath = lpath + "/" + j

                    if fpath.endswith(".pcap"):
                        self.files.extend([(fpath, "Anomalous")])
                        attack += 1
                    else:
                        files = os.listdir(fpath)
                        self.files.extend(
                            [(fpath + "/" + w, j) for w in files if w.endswith(".pcap")]
                        )
                        attack += len(files)
            elif f == "Normal":
                files = os.listdir(lpath)
                self.files.extend(
                    [(lpath + "/" + w, f) for w in files if w.endswith(".pcap")]
                )
                normal += len(files)
            self.fcount = {"Attacks": attack, "Normal": normal}

        print("Directory Scanned successfully: Found {} Files".format(len(self.files)))

    def dzeek(self, mode="default"):
        start_ray()

        zip_path = (
            self.parameters["pcap_path"]
            + self.parameters["ndf_train_row"]["FolderName"]
            + "/"
            + self.parameters["ndf_train_row"]["Filename"]
        )

        print(zip_path, os.path.dirname(zip_path))
        print(self.label_df)

        conn_file = os.path.dirname(zip_path) + "/conn.log"

        if not os.path.exists(conn_file):
            print("Missing file")
            () + 1
        log_to_df = LogToDataFrame()
        zeek_df = log_to_df.create_dataframe(conn_file)
        ndf = self.label_df.merge(zeek_df, how="left", on=["uid"], suffixes=["", "_y"])
        ndf["duration"] = pd.to_timedelta(ndf["duration"]).dt.total_seconds()
        param = self.func_params["param"]
        ndf["ts"] = pd.to_datetime(ndf["ts"])
        print(param)
        print(ndf.columns)
        uids = ndf["uid"]
        ndf = ndf[param]
        ndf.columns = [f"FE::{i}" for i in ndf.columns]
        ndf["Label"] = self.parameters["ndf_train_row"]["Label"]
        ndf["flow_ID"] = uids

        print(ndf.head())

        print("Finished\t", ndf.shape)
        return ndf

    def d_custom(self, mode="default"):
        start_ray()

        st = time.time()
        print("Reading Pcap Files")
        self.csv_files = []

        layers = {}

        sv_folder = self.parameters["save_directory"] + "CSV/"

        if os.path.exists(sv_folder):

            csv_path = self.parameters["save_directory"] + "/CSV/*/*"

            files = glob.glob(csv_path, recursive=True)

            for f in files:
                try:
                    os.remove(f)
                    print(f)
                except OSError as e:
                    print("Error: %s : %s" % (f, e.strerror))

            files = glob.glob(
                self.parameters["save_directory"] + "pdml_*", recursive=True
            )

            for f in files:
                try:
                    shutil.rmtree(f)
                    print(f)
                except OSError as e:
                    print("Error: %s : %s" % (f, e.strerror))

        else:
            os.makedirs(sv_folder)

        zip_path = (
            "/data/ray/mliot/pcaps/"
            + self.parameters["ndf_train_row"]["FolderName"]
            + "/"
            + self.parameters["ndf_train_row"]["Filename"]
        )
        print(self.label_df)
        flows = self.label_df["uid"].to_numpy().tolist()

        print(zip_path)
        result_ids = []
        results = []

        counter = 0
        each = 100
        lss_count = 50

        lss = np.array_split(flows, lss_count)

        target_dir = self.parameters["save_directory"] + "data/ray/temp/"
        if not os.path.exists(target_dir):

            os.makedirs(target_dir)

        csv_path = target_dir + "*.csv"

        files = glob.glob(csv_path, recursive=True)

        for f in files:
            try:
                os.remove(f)
                print(f)
            except OSError as e:
                print("Error: %s : %s" % (f, e.strerror))

        print("Extraction started")

        print("Extraction finished")

        for counter, eachlss in enumerate(lss):

            print(counter)

            to_pass = (counter, len(flows))
            F1 = Rem.options().remote(self.parameters)

            svg = target_dir + str(counter) + ".csv"
            if os.path.exists(svg):
                os.remove(svg)
            result_ids.append(
                F1.pkt_read_tcptrace.remote(
                    eachlss,
                    zip_path,
                    layers,
                    mapper,
                    to_pass,
                    svg,
                    self.func_params,
                )
            )
            results = ray.get(result_ids)

        print("WAiTING")
        results = ray.get(result_ids)

        print(results)
        print("concatting")
        time.sleep(5)
        results = [x for x in results if x != "-1"]
        print(results)

        df_2 = pd.concat(map(pd.read_csv, results))

        if "packet__time" in df_2.columns:
            df_2["packet__time"] = pd.to_datetime(df_2["packet__time"])
        df_2["Label"] = self.parameters["ndf_train_row"]["Label"]

        print(df_2.head())
        print(df_2.shape)
        shutil.rmtree(target_dir)

        return df_2

    def dflow(self, mode="default"):
        start_ray()

        st = time.time()
        print("Reading Pcap Files")
        self.csv_files = []

        layers = {}

        for field in self.fields:
            field_split = field.split("__")

            if field_split[0] not in layers:
                layers[field_split[0]] = []
            print(field, layers)
            layers[field_split[0]].append(field_split[1])

        print(layers)
        sv_folder = self.parameters["save_directory"] + "CSV/"
        print(sv_folder)
        clear_folder(sv_folder)

        print(layers)
        zip_path = f"{self.parameters['zip_prefix']}{self.parameters['ndf_train_row']['FolderName']}/{self.parameters['ndf_train_row']['Filename']}/"
        print(self.label_df, "INSIDE")
        print(zip_path)

        # () + 1
        flows = self.label_df["uid"].to_numpy().tolist()

        print(zip_path)
        result_ids = []
        results = []

        counter = 0
        each = 100
        lss = np.array_split(flows, self.parameters["flows_split"])
        print(len(flows), self.parameters["flows_split"], len(lss))
        flist = []
        for counter, flow in enumerate(flows):
            print(counter, len(flows))
            flist.append(f"{zip_path}{flow}.pcap")

        #     container_client = service.get_container_client("netsharecmu")

        #     # zipfilename = 'rahul/pcaps/cicids2017/flows/Tuesday/pcaps/C001mc4UReJDop1D6l.pcap'
        #     zipfilename = "rahul/pcaps/cicids2017/flows/Tuesday/pcaps.zip"

        #     blob_data = container_client.download_blob(zipfilename)

        #     print(zipfilename)
        #     blob_bytes = blob_data.content_as_bytes()
        #     inmem = BytesIO(blob_bytes)
        #     print(inmem)
        #     myzip = ZipFile(inmem)
        #     print(myzip.namelist())
        # print(flist[0:10])
        # file = "pcaps/" + lfor
        # file = "pcaps/" + lfor

        print(len(flist))
        print("Extraction started")
        print(flist[0:10])
        print("Extraction finished")

        for counter, eachlss in enumerate(lss):

            print(counter)

            to_pass = (counter, len(flows))
            F1 = Rem.options().remote(self.parameters)
            # svg
            result_ids.append(
                F1.pkt_read_flow.remote(
                    eachlss,
                    zip_path,
                    layers,
                    mapper,
                    to_pass,
                    self.func_params,
                    container_client,
                )
            )
            # if counter > 5:
            #     break
        print("WAiTING")
        results = ray.get(result_ids)

        # print(results)
        print("concatting")
        # results = [x for x in results if x != "-1"]
        # print(results)

        df_2 = pd1.concat(results)
        if "packet__time" in df_2.columns:
            df_2["packet__time"] = pd.to_datetime(df_2["packet__time"])
        df_2["Label"] = self.parameters["ndf_train_row"]["Label"]

        print(df_2)
        () + 1

        return df_2

        () + 1

        # target_dir = self.parameters["save_directory"] + "data/ray/temp/"
        # if not os.path.exists(target_dir):

        #     os.makedirs(target_dir)

        # csv_path = target_dir + "*.csv"

        # files = glob(csv_path, recursive=True)

        # for f in files:
        #     try:
        #         os.remove(f)
        #         print(f)
        #     except OSError as e:
        #         print("Error: %s : %s" % (f, e.strerror))

        # with ZipFile(zip_path, "r") as zf:

        #     flist = []
        #     for counter, flow in enumerate(flows):
        #         print(counter, len(flows))
        #         lfor = flow + ".pcap"
        #         file = "pcaps/" + lfor
        #         flist.append(file)

        #     print(len(flist))
        #     print("Extraction started")

        # print("WAiTING")
        # results = ray.get(result_ids)

        # print(results)
        # print("concatting")
        # time.sleep(5)
        # results = [x for x in results if x != "-1"]
        # print(results)

        # df_2 = pd.concat(map(pd.read_csv, results))

        # if "packet__time" in df_2.columns:
        #     df_2["packet__time"] = pd.to_datetime(df_2["packet__time"])
        # df_2["Label"] = self.parameters["ndf_train_row"]["Label"]

        # print(df_2.head())
        # print(df_2.shape)
        # shutil.rmtree(target_dir)

        # return df_2

    def df(self, mode="default"):

        start_ray()

        st = time.time()
        print("Reading Pcap Files")
        self.csv_files = []

        layers = {}

        for field in self.fields:
            field_split = field.split("__")

            if field_split[0] not in layers:
                layers[field_split[0]] = []
            print(field, layers)
            layers[field_split[0]].append(field_split[1])

        print(layers)
        sv_folder = self.parameters["save_directory"] + "CSV/"

        if os.path.exists(sv_folder):

            csv_path = self.parameters["save_directory"] + "/CSV/*/*"

            files = glob.glob(csv_path, recursive=True)

            for f in files:
                try:
                    os.remove(f)
                    print(f)
                except OSError as e:
                    print("Error: %s : %s" % (f, e.strerror))

        else:
            os.makedirs(sv_folder)

        files = glob.glob(self.parameters["save_directory"] + "pdml_*", recursive=True)

        for f in files:
            try:
                shutil.rmtree(f)
                print(f)
            except OSError as e:
                print("Error: %s : %s" % (f, e.strerror))

        local_hostname = ray._private.services.get_node_ip_address()
        node_id = f"node:{local_hostname}"
        print(node_id)

        self_mapper = {}
        counter = 0
        for times in range(50):
            finished = 1
            result_ids = []
            bfile = {}
            print("Total files to process", self.files)

            for file in self.files:
                print(
                    "Processing File",
                    "times\t",
                    times,
                    file[0],
                    file[1],
                    len(self.csv_files),
                    len(self.files),
                )

                base_path = ntpath.basename(file[0])
                base_path_woext = os.path.splitext(base_path)[0]
                print(base_path_woext, times)
                pcap_split_path = sv_folder + str(base_path_woext) + "/"
                if not os.path.exists(pcap_split_path):
                    os.makedirs(pcap_split_path)

                template = "editcap -c {0} {1} {2} -F pcap"

                if mode == "nprint" and "-c" in self.func_params["param"]:
                    each_len = 1000000000
                elif mode == "nprint":
                    each_len = 50000
                elif mode == "zeek":
                    each_len = 800000
                elif mode == "pdml":
                    each_len = 5000

                else:
                    each_len = 100000

                act_command = template.format(
                    each_len,
                    file[0],
                    pcap_split_path + "out.pcap",
                )

                if mode == "nprint":
                    layers = {"nprint": ""}
                if mode == "zeek":
                    layers = {"zeek": ""}
                if mode == "pdml":
                    layers = {"pdml": ""}

                if times == 0:
                    print("RUNNING")
                    print(act_command)
                    execs = os.system(act_command)

                    time.sleep(10)
                for layer, funs in layers.items():

                    time.sleep(5)

                    all_inds = glob.glob(pcap_split_path + "out*.pcap")
                    print(all_inds)
                    dist = 1

                    for each_small_csv in all_inds:
                        if each_small_csv not in self_mapper:
                            self_mapper[each_small_csv] = file

                        if each_small_csv not in bfile:
                            bfile[each_small_csv] = []

                        csv_sv_path = (
                            os.path.splitext(each_small_csv)[0]
                            + "_head_"
                            + layer
                            + ".csv"
                        )

                        bfile[each_small_csv].append((csv_sv_path, file[1]))

                        if os.path.exists(csv_sv_path):
                            continue
                        finished = 0
                        print("DIST\t", dist, "\t", each_small_csv, csv_sv_path)

                        if dist == 0:
                            () + 1
                            if mode == "nprint":
                                status = nprint_reader(
                                    each_small_csv, csv_sv_path, file[1]
                                )
                            else:
                                status = pkd_read_pypacker(
                                    layer, funs, each_small_csv, csv_sv_path, mapper
                                )
                        else:
                            if mode == "nprint":
                                F1 = Rem.remote(self.parameters)

                                param = self.func_params["param"]

                                result_ids.append(
                                    F1.nprint_reader.remote(
                                        each_small_csv, csv_sv_path, file[1], param
                                    )
                                )

                            elif mode == "zeek":
                                F1 = Rem.remote(self.parameters)
                                param = self.func_params["param"]

                                result_ids.append(
                                    F1.zeek_reader.remote(
                                        each_small_csv, csv_sv_path, file[1], param
                                    )
                                )

                            elif mode == "pdml":
                                F1 = Rem.remote(self.parameters)
                                print(F1)

                                param = self.func_params["param"]

                                result_ids.append(
                                    F1.wireshark_reader.remote(
                                        each_small_csv,
                                        csv_sv_path,
                                        file[1],
                                        param,
                                        counter,
                                    )
                                )
                                counter += 1
                            else:
                                F1 = Rem.options().remote(self.parameters)

                                param = self.func_params["param"]
                                result_ids.append(
                                    F1.pkd_read_pypacker.remote(
                                        layer, funs, each_small_csv, csv_sv_path, mapper
                                    )
                                )

            results = ray.get(result_ids)
            print("Trying to finish")
            break
            if finished == 1:
                print("\n\n", finished, "Finished \n\n")
                break
            print("\n\n\n\n\n", results, "\n\n\n\n\n")

        sys.stdout.flush()

        print("\n\n\n\nElapsed for running again", (time.time() - st))
        time.sleep(25)

        print(bfile)

        if mode == "nprint" or mode == "zeek" or mode == "pdml":
            start_ray()

            flist = []

            for k1, v1 in bfile.items():
                print(k1, v1)

                eachfile, label = v1[0]
                flist.append(eachfile)
            print("MERGING", flist)

            df = pd1.concat([pd1.read_csv(i) for i in flist])

            df = df.fillna(0)

            print(df.shape)

            print("Elapsed for total", (time.time() - st))

            print(
                "Successfully Read all Pcaps, labelled all packets and stored as CSV with required fields"
            )
            time.sleep(1)

            shutil.rmtree(sv_folder, ignore_errors=True)
            time.sleep(5)
            print("DOne overall", Counter(df["Label"]))

            return df

        else:
            df = pd.DataFrame()
            print(self_mapper)
            for k1, v1 in bfile.items():

                df2 = pd.DataFrame()
                for eachfile, label in v1:
                    if not os.path.exists(eachfile):
                        print("waiting for file", eachfile)
                        () + 1
                    df3 = pd.read_csv(eachfile)

                    print(df3)
                    df2 = pd.concat([df2, df3], axis=1)
                    df2["Label"] = label

                df = pd.concat([df, df2], axis=0)
            if "packet__time" in df.columns:
                df["packet__time"] = pd.to_datetime(df["packet__time"])

            print(df)
            print(df.head())
            print(df.shape)
            if df.shape[0] == 0:
                print("DataFrame is Empty, Please check the input file numbers")
                () + 1
            print("Elapsed for total", (time.time() - st))

            print(
                "Successfully Read all Pcaps, labelled all packets and stored as CSV with required fields"
            )
            time.sleep(5)

            shutil.rmtree(sv_folder, ignore_errors=True)
            time.sleep(5)
            print("Done Overall")
            return df

    def nprint(self):
        st = time.time()
        print("Reading Pcap Files")
        self.csv_files = []

        for times in range(5):
            finished = 1
            result_ids = []
            bfile = {}

            for file in self.files:
                print(
                    "Processing File",
                    "times\t",
                    times,
                    file[0],
                    file[1],
                    len(self.csv_files),
                    len(self.files),
                )

                base_path = ntpath.basename(file[0])
                base_path_woext = os.path.splitext(base_path)[0]
                print(base_path_woext, times)
                pcap_split_path = self.path + "/CSV/" + str(base_path_woext) + "/"
                if not os.path.exists(pcap_split_path):
                    os.makedirs(pcap_split_path)

                template = "editcap -c {0} {1} {2} -F pcap"

                act_command = template.format(
                    20000,
                    file[0],
                    pcap_split_path + "out.pcap",
                )
                if times == 0:

                    os.system(act_command)
                    time.sleep(5)

                all_inds = glob.glob(pcap_split_path + "out*.pcap")

                for each_small_csv in all_inds:
                    if each_small_csv not in bfile:
                        bfile[each_small_csv] = []

                    csv_sv_path = os.path.splitext(each_small_csv)[0] + "_nprint.csv"
                    bfile[each_small_csv].append((csv_sv_path, file[1]))

                    if os.path.exists(csv_sv_path):
                        continue
                    finished = 0
                    print(each_small_csv, csv_sv_path)

                    result_ids.append(
                        nprint_reader.remote(each_small_csv, csv_sv_path, file[1])
                    )

            results = ray.get(result_ids)
            if finished == 1:
                print("\n\n", finished, "Finished \n\n")
                break
            print("\n\n\n\n\n", results, "\n\n\n\n\n")

        sys.stdout.flush()

        print("\n\n\n\nElapsed for running again", (time.time() - st))

        print(bfile)

        df = pd1.DataFrame()

        flist = []

        for k1, v1 in bfile.items():
            print(k1, v1)

            eachfile, label = v1[0]
            flist.append(eachfile)

        df = pd1.concat(map(pd1.read_csv, flist))

        df = df.fillna(0)

        print(df.head())
        print(df.shape)
        print("Elapsed for total", (time.time() - st))

        print(
            "Successfully Read all Pcaps, labelled all packets and stored as CSV with required fields"
        )

        return df

    def wireshark(self):
        st = time.time()
        print("Reading Pcap Files")
        self.csv_files = []

        for times in range(5):
            finished = 1
            result_ids = []
            bfile = {}

            for file in self.files:
                print(
                    "Processing File",
                    "times\t",
                    times,
                    file[0],
                    file[1],
                    len(self.csv_files),
                    len(self.files),
                )

                base_path = ntpath.basename(file[0])
                base_path_woext = os.path.splitext(base_path)[0]
                print(base_path_woext, times)
                pcap_split_path = self.path + "/CSV/" + str(base_path_woext) + "/"
                if not os.path.exists(pcap_split_path):
                    os.makedirs(pcap_split_path)

                template = "editcap -c {0} {1} {2} -F pcap"

                act_command = template.format(
                    20000,
                    file[0],
                    pcap_split_path + "out.pcap",
                )
                if times == 0:
                    os.system(act_command)

                all_inds = glob.glob(pcap_split_path + "out*.pcap")

                for each_small_csv in all_inds:
                    if each_small_csv not in bfile:
                        bfile[each_small_csv] = []

                    csv_sv_path = os.path.splitext(each_small_csv)[0] + "_nprint.csv"
                    bfile[each_small_csv].append((csv_sv_path, file[1]))

                    if os.path.exists(csv_sv_path):
                        continue
                    finished = 0
                    print(each_small_csv, csv_sv_path)

                    result_ids.append(
                        wireshark_reader.remote(each_small_csv, csv_sv_path, file[1])
                    )

            results = ray.get(result_ids)
            if finished == 1:
                print("\n\n", finished, "Finished \n\n")
                break
            print("\n\n\n\n\n", results, "\n\n\n\n\n")

        sys.stdout.flush()

        print("\n\n\n\nElapsed for running again", (time.time() - st))

        print(bfile)

        df = pd1.DataFrame()

        flist = []

        for k1, v1 in bfile.items():
            print(k1, v1)

            eachfile, label = v1[0]
            flist.append(eachfile)

        df = pd1.concat(map(pd1.read_csv, flist))

        df = df.fillna(0)

        print(df.head())
        print(df.shape)
        print("Elapsed for total", (time.time() - st))

        print(
            "Successfully Read all Pcaps, labelled all packets and stored as CSV with required fields"
        )

        return df

    def dataframe(self, split="random", testsize=0.3):

        df_list = []

        df = pd.DataFrame()
        for i in self.csv_files:
            data = pd.read_csv(i)
            df = pd.concat([df, data], ignore_index=True)

        df["packet__time"] = pd.to_datetime(df["packet__time"])

        print(df)
        print(df.head())
        print(type(df))

        return df

    def packetreader(self, packet):
        temp = {}
        temp["packet__time"] = packet.time
        temp["packet__len"] = len(packet)
        temp["packet__protocol"] = "other"
        temp["packet__layers"] = [i.__name__ for i in packet.layers()]
        temp["packet__layercount"] = len(packet.layers())

        for i in temp["packet__layers"]:

            layer = packet.getlayer(i)
            if i == "Raw":
                temp["packet__rawlen"] = len(packet["Raw"].load)
                break

            if i == "TCP":
                temp["packet__protocol"] = "TCP"
            elif i == "UDP":
                temp["packet__protocol"] = "UDP"

            for key, value in layer.fields.items():

                if type(value) == list:
                    try:
                        for r in range(len(value)):
                            temp[i + " " + value[r][0]] = value[r][1]
                    except:
                        temp[i + " " + key] = value
                else:
                    temp[i + " " + key] = value

        if temp["packet __protocol"] == "other":

            if packet.haslayer("ARP"):
                temp["packet__protocol"] = "ARP"

            elif packet.haslayer("ICMP"):
                temp["packet__protocol"] = "ICMP"

            else:
                temp["packet__src"] = packet.src
                temp["packet__dst"] = packet.dst

        self.data.append(temp)
        self.packetindex = self.packetindex + 1


def fe_kitsune(parameters, inp_name, func_params, results):

    df, ty = results[inp_name[0]]
    nstat = netStat()
    headers = nstat.getNetStatHeaders()

    features = pd.DataFrame()
    features["list"] = df.apply(lambda x: FE(x, nstat), axis=1)

    features = features["list"].tolist()

    features = pd.DataFrame(features, columns=range(len(features[0])))

    features["Label"] = df["Label"]

    return features, "dataframe"


def FE(packet, nstat):

    if "NatType" in str(type(packet["packet__time"])):
        vec = nstat.updateGetStats(
            packet["IP__type"],
            str(packet["packet__src"]),
            str(packet["packet__dst"]),
            str(packet["IP__src_s"]),
            str(packet["sport"]),
            str(packet["IP__dst_s"]),
            str(packet["dport"]),
            packet["packet__len"],
            packet["packet__time"],
        )
    else:
        vec = nstat.updateGetStats(
            packet["IP__type"],
            str(packet["packet__src"]),
            str(packet["packet__dst"]),
            str(packet["IP__src_s"]),
            str(packet["sport"]),
            str(packet["IP__dst_s"]),
            str(packet["dport"]),
            packet["packet__len"],
            packet["packet__time"].timestamp(),
        )
    return vec


class incStat:
    def __init__(self, Lambda, ID, init_time=0, isTypeDiff=False):
        self.ID = ID
        self.CF1 = 0
        self.CF2 = 0
        self.w = 1e-20
        self.isTypeDiff = isTypeDiff
        self.Lambda = Lambda
        self.lastTimestamp = init_time
        self.cur_mean = np.nan
        self.cur_var = np.nan
        self.cur_std = np.nan
        self.covs = []

    def insert(self, v, t=0):
        if self.isTypeDiff:
            dif = t - self.lastTimestamp
            if dif > 0:
                v = dif
            else:
                v = 0
        self.processDecay(t)

        self.CF1 += v
        self.CF2 += math.pow(v, 2)
        self.w += 1
        self.cur_mean = np.nan
        self.cur_var = np.nan
        self.cur_std = np.nan

        for cov in self.covs:
            cov.update_cov(self.ID, v, t)

    def processDecay(self, timestamp):
        factor = 1

        timeDiff = timestamp - self.lastTimestamp
        if timeDiff > 0:
            factor = math.pow(2, (-self.Lambda * timeDiff))
            self.CF1 = self.CF1 * factor
            self.CF2 = self.CF2 * factor
            self.w = self.w * factor
            self.lastTimestamp = timestamp
        return factor

    def weight(self):
        return self.w

    def mean(self):
        if math.isnan(self.cur_mean):
            self.cur_mean = self.CF1 / self.w
        return self.cur_mean

    def var(self):
        if math.isnan(self.cur_var):
            self.cur_var = abs(self.CF2 / self.w - math.pow(self.mean(), 2))
        return self.cur_var

    def std(self):
        if math.isnan(self.cur_std):
            self.cur_std = math.sqrt(self.var())
        return self.cur_std

    def cov(self, ID2):
        for cov in self.covs:
            if cov.incStats[0].ID == ID2 or cov.incStats[1].ID == ID2:
                return cov.cov()
        return [np.nan]

    def pcc(self, ID2):
        for cov in self.covs:
            if cov.incStats[0].ID == ID2 or cov.incStats[1].ID == ID2:
                return cov.pcc()
        return [np.nan]

    def cov_pcc(self, ID2):
        for cov in self.covs:
            if cov.incStats[0].ID == ID2 or cov.incStats[1].ID == ID2:
                return cov.get_stats1()
        return [np.nan] * 2

    def radius(self, other_incStats):
        A = self.var() ** 2
        for incS in other_incStats:
            A += incS.var() ** 2
        return math.sqrt(A)

    def magnitude(self, other_incStats):
        A = math.pow(self.mean(), 2)
        for incS in other_incStats:
            A += math.pow(incS.mean(), 2)
        return math.sqrt(A)

    def allstats_1D(self):
        self.cur_mean = self.CF1 / self.w
        self.cur_var = abs(self.CF2 / self.w - math.pow(self.cur_mean, 2))
        return [self.w, self.cur_mean, self.cur_var]

    def allstats_2D(self, ID2):
        stats1D = self.allstats_1D()

        stats2D = [np.nan] * 4
        for cov in self.covs:
            if cov.incStats[0].ID == ID2 or cov.incStats[1].ID == ID2:
                stats2D = cov.get_stats2()
                break
        return stats1D + stats2D

    def getHeaders_1D(self, suffix=True):
        if self.ID is None:
            s0 = ""
        else:
            s0 = "_0"
        if suffix:
            s0 = "_" + self.ID
        headers = ["weight" + s0, "mean" + s0, "std" + s0]
        return headers

    def getHeaders_2D(self, ID2, suffix=True):
        hdrs1D = self.getHeaders_1D(suffix)
        if self.ID is None:
            s0 = ""
            s1 = ""
        else:
            s0 = "_0"
            s1 = "_1"
        if suffix:
            s0 = "_" + self.ID
            s1 = "_" + ID2
        hdrs2D = [
            "radius_" + s0 + "_" + s1,
            "magnitude_" + s0 + "_" + s1,
            "covariance_" + s0 + "_" + s1,
            "pcc_" + s0 + "_" + s1,
        ]
        return hdrs1D + hdrs2D


class incStat_cov:
    def __init__(self, incS1, incS2, init_time=0):

        self.incStats = [incS1, incS2]
        self.lastRes = [0, 0]

        self.CF3 = 0
        self.w3 = 1e-20
        self.lastTimestamp_cf3 = init_time

    def update_cov(self, ID, v, t):

        if ID == self.incStats[0].ID:
            inc = 0
        elif ID == self.incStats[1].ID:
            inc = 1
        else:
            print("update_cov ID error")
            return

        self.incStats[not (inc)].processDecay(t)

        self.processDecay(t, inc)

        res = v - self.incStats[inc].mean()
        resid = (v - self.incStats[inc].mean()) * self.lastRes[not (inc)]
        self.CF3 += resid
        self.w3 += 1
        self.lastRes[inc] = res

    def processDecay(self, t, micro_inc_indx):
        factor = 1

        timeDiffs_cf3 = t - self.lastTimestamp_cf3
        if timeDiffs_cf3 > 0:
            factor = math.pow(
                2, (-(self.incStats[micro_inc_indx].Lambda) * timeDiffs_cf3)
            )
            self.CF3 *= factor
            self.w3 *= factor
            self.lastTimestamp_cf3 = t
            self.lastRes[micro_inc_indx] *= factor
        return factor

    def cov(self):
        return self.CF3 / self.w3

    def pcc(self):
        ss = self.incStats[0].std() * self.incStats[1].std()
        if ss != 0:
            return self.cov() / ss
        else:
            return 0

    def get_stats1(self):
        return [self.cov(), self.pcc()]

    def get_stats2(self):
        return [
            self.incStats[0].radius([self.incStats[1]]),
            self.incStats[0].magnitude([self.incStats[1]]),
            self.cov(),
            self.pcc(),
        ]

    def get_stats3(self):
        return [
            self.incStats[0].w,
            self.incStats[0].mean(),
            self.incStats[0].std(),
            self.incStats[1].w,
            self.incStats[1].mean(),
            self.incStats[1].std(),
            self.cov(),
            self.pcc(),
        ]

    def get_stats4(self):
        return [
            self.incStats[0].w,
            self.incStats[0].mean(),
            self.incStats[0].std(),
            self.incStats[1].w,
            self.incStats[1].mean(),
            self.incStats[1].std(),
            self.incStats[0].radius([self.incStats[1]]),
            self.incStats[0].magnitude([self.incStats[1]]),
            self.cov(),
            self.pcc(),
        ]

    def getHeaders(self, ver, suffix=True):
        headers = []
        s0 = "0"
        s1 = "1"
        if suffix:
            s0 = self.incStats[0].ID
            s1 = self.incStats[1].ID

        if ver == 1:
            headers = ["covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        if ver == 2:
            headers = [
                "radius_" + s0 + "_" + s1,
                "magnitude_" + s0 + "_" + s1,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1,
            ]
        if ver == 3:
            headers = [
                "weight_" + s0,
                "mean_" + s0,
                "std_" + s0,
                "weight_" + s1,
                "mean_" + s1,
                "std_" + s1,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1,
            ]
        if ver == 4:
            headers = [
                "weight_" + s0,
                "mean_" + s0,
                "std_" + s0,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1,
            ]
        if ver == 5:
            headers = [
                "weight_" + s0,
                "mean_" + s0,
                "std_" + s0,
                "weight_" + s1,
                "mean_" + s1,
                "std_" + s1,
                "radius_" + s0 + "_" + s1,
                "magnitude_" + s0 + "_" + s1,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1,
            ]
        return headers


class Brute:
    def __init__(self):
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        imputer = SimpleImputer()
        standardizer = StandardScaler()
        automl = AutoML(n_jobs=-1)

        self.automl_pipeline = Pipeline([("automl", automl)])

    def fit(self, x, y):
        settings = {
            "time_budget": 60,
            "metric": "accuracy",
            "task": "classification",
            "log_file_name": "airlines_experiment.log",
        }

        self.automl_pipeline.fit(x, y)
        return self

    def predict(self, x):
        return self.automl_pipeline.predict(x)


class incStatDB:
    def __init__(self, limit=np.Inf, default_lambda=np.nan):
        self.HT = dict()
        self.limit = limit
        self.df_lambda = default_lambda

    def get_lambda(self, Lambda):
        if not np.isnan(self.df_lambda):
            Lambda = self.df_lambda
        return Lambda

    def register(self, ID, Lambda=1, init_time=0, isTypeDiff=False):

        Lambda = self.get_lambda(Lambda)

        key = ID + "_" + str(Lambda)
        incS = self.HT.get(key)
        if incS is None:
            if len(self.HT) + 1 > self.limit:
                raise LookupError(
                    "Adding Entry:\n"
                    + key
                    + "\nwould exceed incStatHT 1D limit of "
                    + str(self.limit)
                    + ".\nObservation Rejected."
                )
            incS = incStat(Lambda, ID, init_time, isTypeDiff)
            self.HT[key] = incS
        return incS

    def register_cov(self, ID1, ID2, Lambda=1, init_time=0, isTypeDiff=False):

        Lambda = self.get_lambda(Lambda)

        incS1 = self.register(ID1, Lambda, init_time, isTypeDiff)
        incS2 = self.register(ID2, Lambda, init_time, isTypeDiff)

        for cov in incS1.covs:
            if cov.incStats[0].ID == ID2 or cov.incStats[1].ID == ID2:
                return cov

        inc_cov = incStat_cov(incS1, incS2, init_time)
        incS1.covs.append(inc_cov)
        incS2.covs.append(inc_cov)
        return inc_cov

    def update(self, ID, t, v, Lambda=1, isTypeDiff=False):
        incS = self.register(ID, Lambda, t, isTypeDiff)
        incS.insert(v, t)
        return incS

    def get_1D_Stats(self, ID, Lambda=1):

        Lambda = self.get_lambda(Lambda)

        incS = self.HT.get(ID + "_" + str(Lambda))
        if incS is None:
            return [np.na] * 3
        else:
            return incS.allstats_1D()

    def get_2D_Stats(self, ID1, ID2, Lambda=1):

        Lambda = self.get_lambda(Lambda)

        incS1 = self.HT.get(ID1 + "_" + str(Lambda))
        if incS1 is None:
            return [np.na] * 2

        return incS1.cov_pcc(ID2)

    def get_all_2D_Stats(self, ID, Lambda=1):

        Lambda = self.get_lambda(Lambda)

        incS1 = self.HT.get(ID + "_" + str(Lambda))
        if incS1 is None:
            return ([], [])

        stats = []
        IDs = []
        for cov in incS1.covs:
            stats.append(cov.get_stats1())
            IDs.append([cov.incStats[0].ID, cov.incStats[1].ID])
        return stats, IDs

    def get_nD_Stats(self, IDs, Lambda=1):

        Lambda = self.get_lambda(Lambda)

        incStats = []
        for ID in IDs:
            incS = self.HT.get(ID + "_" + str(Lambda))
            if incS is not None:
                incStats.append(incS)

        rad = 0
        mag = 0
        for incS in incStats:
            rad += incS.var()
            mag += incS.mean() ** 2

        return [np.sqrt(rad), np.sqrt(mag)]

    def update_get_1D_Stats(self, ID, t, v, Lambda=1, isTypeDiff=False):
        incS = self.update(ID, t, v, Lambda, isTypeDiff)
        return incS.allstats_1D()

    def update_get_2D_Stats(self, ID1, ID2, t1, v1, Lambda=1, level=1):

        inc_cov = self.register_cov(ID1, ID2, Lambda, t1)

        inc_cov.update_cov(ID1, v1, t1)
        if level == 1:
            return inc_cov.get_stats1()
        else:
            return inc_cov.get_stats2()

    def update_get_1D2D_Stats(self, ID1, ID2, t1, v1, Lambda=1):
        return self.update_get_1D_Stats(ID1, t1, v1, Lambda) + self.update_get_2D_Stats(
            ID1, ID2, t1, v1, Lambda, level=2
        )

    def getHeaders_1D(self, Lambda=1, ID=None):

        Lambda = self.get_lambda(Lambda)
        hdrs = incStat(Lambda, ID).getHeaders_1D(suffix=False)
        return [str(Lambda) + "_" + s for s in hdrs]

    def getHeaders_2D(self, Lambda=1, IDs=None, ver=1):

        Lambda = self.get_lambda(Lambda)
        if IDs is None:
            IDs = [0, 1]
        hdrs = incStat_cov(
            incStat(Lambda, IDs[0]), incStat(Lambda, IDs[0]), Lambda
        ).getHeaders(ver, suffix=False)
        return [str(Lambda) + "_" + s for s in hdrs]

    def getHeaders_1D2D(self, Lambda=1, IDs=None, ver=1):

        Lambda = self.get_lambda(Lambda)
        if IDs is None:
            IDs = [0, 1]
        hdrs1D = self.getHeaders_1D(Lambda, IDs[0])
        hdrs2D = self.getHeaders_2D(Lambda, IDs, ver)
        return hdrs1D + hdrs2D

    def getHeaders_nD(self, Lambda=1, IDs=[]):

        ID = ":"
        for s in IDs:
            ID += "_" + s
        Lambda = self.get_lambda(Lambda)
        hdrs = ["radius" + ID, "magnitude" + ID]
        return [str(Lambda) + "_" + s for s in hdrs]

    def cleanOutOldRecords(self, cutoffWeight, curTime):
        n = 0
        dump = sorted(self.HT.items(), key=lambda tup: tup[1][0].getMaxW(curTime))
        for entry in dump:
            entry[1][0].processDecay(curTime)
            W = entry[1][0].w
            if W <= cutoffWeight:
                key = entry[0]
                del entry[1][0]
                del self.HT[key]
                n = n + 1
            elif W > cutoffWeight:
                break
        return n


class netStat:
    def __init__(self, Lambdas=np.nan, HostLimit=100000, HostSimplexLimit=100000):

        if np.isnan(Lambdas):
            self.Lambdas = [5, 3, 1, 0.1, 0.01]
        else:
            self.Lambdas = Lambdas

        self.HostLimit = HostLimit
        self.SessionLimit = HostSimplexLimit * self.HostLimit * self.HostLimit
        self.MAC_HostLimit = self.HostLimit * 10

        self.HT_jit = incStatDB(limit=self.HostLimit * self.HostLimit)
        self.HT_MI = incStatDB(limit=self.MAC_HostLimit)
        self.HT_H = incStatDB(limit=self.HostLimit)
        self.HT_Hp = incStatDB(limit=self.SessionLimit)

    def updateGetStats(
        self,
        IPtype,
        srcMAC,
        dstMAC,
        srcIP,
        srcProtocol,
        dstIP,
        dstProtocol,
        datagramSize,
        timestamp,
    ):

        Hstat = np.zeros(
            (
                3
                * len(
                    self.Lambdas,
                )
            )
        )
        for i in range(len(self.Lambdas)):
            Hstat[(i * 3) : ((i + 1) * 3)] = self.HT_H.update_get_1D_Stats(
                srcIP, timestamp, datagramSize, self.Lambdas[i]
            )

        MIstat = np.zeros(
            (
                3
                * len(
                    self.Lambdas,
                )
            )
        )
        for i in range(len(self.Lambdas)):
            MIstat[(i * 3) : ((i + 1) * 3)] = self.HT_MI.update_get_1D_Stats(
                srcMAC + srcIP, timestamp, datagramSize, self.Lambdas[i]
            )

        HHstat = np.zeros(
            (
                7
                * len(
                    self.Lambdas,
                )
            )
        )
        for i in range(len(self.Lambdas)):
            HHstat[(i * 7) : ((i + 1) * 7)] = self.HT_H.update_get_1D2D_Stats(
                srcIP, dstIP, timestamp, datagramSize, self.Lambdas[i]
            )

        HHstat_jit = np.zeros(
            (
                3
                * len(
                    self.Lambdas,
                )
            )
        )
        for i in range(len(self.Lambdas)):
            HHstat_jit[(i * 3) : ((i + 1) * 3)] = self.HT_jit.update_get_1D_Stats(
                srcIP + dstIP, timestamp, 0, self.Lambdas[i], isTypeDiff=True
            )

        HpHpstat = np.zeros(
            (
                7
                * len(
                    self.Lambdas,
                )
            )
        )
        if srcProtocol == "arp":
            for i in range(len(self.Lambdas)):
                HpHpstat[(i * 7) : ((i + 1) * 7)] = self.HT_Hp.update_get_1D2D_Stats(
                    srcMAC, dstMAC, timestamp, datagramSize, self.Lambdas[i]
                )
        else:
            for i in range(len(self.Lambdas)):
                HpHpstat[(i * 7) : ((i + 1) * 7)] = self.HT_Hp.update_get_1D2D_Stats(
                    srcIP + srcProtocol,
                    dstIP + dstProtocol,
                    timestamp,
                    datagramSize,
                    self.Lambdas[i],
                )

        return np.concatenate((MIstat, Hstat, HHstat, HHstat_jit, HpHpstat))

    def getNetStatHeaders(self):
        MIstat_headers = []
        Hstat_headers = []
        HHstat_headers = []
        HHjitstat_headers = []
        HpHpstat_headers = []

        for i in range(len(self.Lambdas)):
            MIstat_headers += [
                "MI_dir_" + h
                for h in self.HT_MI.getHeaders_1D(Lambda=self.Lambdas[i], ID=None)
            ]
            Hstat_headers += [
                "H_stat" + h for h in self.HT_H.getHeaders_1D(Lambda=self.Lambdas)
            ]
            HHstat_headers += [
                "HH_" + h
                for h in self.HT_H.getHeaders_1D2D(
                    Lambda=self.Lambdas[i], IDs=None, ver=2
                )
            ]
            HHjitstat_headers += [
                "HH_jit_" + h
                for h in self.HT_jit.getHeaders_1D(Lambda=self.Lambdas[i], ID=None)
            ]
            HpHpstat_headers += [
                "HpHp_" + h
                for h in self.HT_Hp.getHeaders_1D2D(
                    Lambda=self.Lambdas[i], IDs=None, ver=2
                )
            ]
        return (
            MIstat_headers
            + Hstat_headers
            + HHstat_headers
            + HHjitstat_headers
            + HpHpstat_headers
        )


class clustering:
    def __init__(self, on="features", maxcluster=10, method="Incremental"):

        self.type = on
        self.size = maxcluster
        self.method = method
        self.model = None
        self.columns = None
        self.clusters = None

    def fit(self, X):

        if isinstance(X, pd.DataFrame):

            self.columns = X.columns
            X = X.to_numpy()

        if self.method == "Incremental":
            cls = IncClustering(n=X.shape[1], maxsize=self.size)

        elif self.method == "Agglomerative":
            cls = FeatureAgglomeration(n_clusters=X.shape[1] / self.maxsize)

        elif self.method == "Kmeans":
            cls = KMeans(
                n_clusters=X.shape[1] / self.maxsize,
                max_iter=2000,
            )
        elif self.method == "Kmeansminibatch":
            cls = MiniBatchKMeans(batch_size=1, n_clusters=X.shape[1] / self.maxsize)

        self.model = cls.fit(X)

        return self

    def predict(self, Xtest):

        y_pred = self.model.predict(Xtest)
        return y_pred

    def transform(self, Xtest):

        y_pred = self.model.transform(Xtest)
        return y_pred

    def save(path):
        pass


class IncClustering:
    def __init__(self, n=118, maxsize=10):

        self.n = n

        self.c = np.zeros(n)
        self.c_r = np.zeros(n)
        self.c_rs = np.zeros(n)
        self.C = np.zeros((n, n))
        self.N = 0
        self.maxsize = maxsize
        self.fmap = None

    def update(self, x):
        self.N += 1
        self.c += x
        c_rt = x - self.c / self.N
        self.c_r += c_rt
        self.c_rs += c_rt**2
        self.C += np.outer(c_rt, c_rt)

    def fit(self, X):

        for i in range(X.shape[0]):
            self.update(X[i, :])

        self.fmap = self.cluster(self.maxsize)

        return self

    def corrDist(self):
        c_rs_sqrt = np.sqrt(self.c_rs)
        C_rs_sqrt = np.outer(c_rs_sqrt, c_rs_sqrt)
        C_rs_sqrt[C_rs_sqrt == 0] = 1e-100
        D = 1 - self.C / C_rs_sqrt
        D[D < 0] = 0
        return D

    def cluster(self, maxClust):
        D = self.corrDist()
        Z = linkage(D[np.triu_indices(self.n, 1)])
        if maxClust < 1:
            maxClust = 1
        if maxClust > self.n:
            maxClust = self.n
        map = self.__breakClust__(to_tree(Z), maxClust)
        return map

    def __breakClust__(self, dendro, maxClust):
        if dendro.count <= maxClust:
            return [dendro.pre_order()]
        return self.__breakClust__(dendro.get_left(), maxClust) + self.__breakClust__(
            dendro.get_right(), maxClust
        )

    def transform(self, Xtest):

        return self.fmap

    def predict(self, Xtest):

        return self.fmap


class Ensemble:
    def __init__(self, models=[]):

        self.split_ratio = 0.2
        self.models = [
            KNeighborsClassifier(algorithm="kd_tree"),
            LinearSVC(dual=False, class_weight="balanced", max_iter=5000),
            DecisionTreeClassifier(),
            RandomForestClassifier(
                n_estimators=100,
                max_depth=None,
                class_weight="balanced",
                criterion="entropy",
            ),
            neuralnetwork(
                feature_dim=11, hidden_layers=[11, 11, 11, 11], output_layer=1
            ),
        ]
        if len(models):
            self.models = models

        self.names = [clf.__class__.__name__ for clf in self.models]
        self.trained = []
        self.count = len(self.models)
        print("Models Initialized Successfully")

    def fit(self, X_train=None, Y=None, save_directory=""):

        print("Splitting Dataset for Validation")
        self.xtrain, self.xval, self.ytrain, self.yval = train_test_split(
            X_train, Y, test_size=self.split_ratio, stratify=Y
        )
        print("Training Dataset size is", self.xtrain.shape)

        for i in range(len(self.models)):
            print("Training Model", self.names[i])
            clf = self.models[i]
            print("Model Initialized")
            clf = clf.fit(self.xtrain, self.ytrain)
            print("Model Trained")
            self.trained.append(clf)
            print("Stored Model Successfully")

        print("Testing on Validation Dataset")
        o, t = self.predict()

        return self

    def predict(self, xtest=None, ytest=None):
        output = []
        scores = []
        if xtest is None:
            xtest = self.xval
            ytest = self.yval

        print("Predicting Labels")
        for clf in self.trained:
            y_pred = clf.predict(xtest)
            output.append(y_pred)
            scores.append(metrics(y_pred, ytest))

        print("Creating Metrics Table")
        table = pd.DataFrame(index=self.names, data=scores)
        return output, table

    def save(self, directory=""):

        print("Storing Models in the directory ", directory)
        for clf in self.trained:

            path = directory + clf.__class__.__name__ + ".pickle"
            name = type(clf).__module__.split(".")[0]
            if name == "sklearn":
                with open(path, "wb") as f:
                    pickle.dump(clf, f)
            else:
                path = directory + clf.__class__.__name__ + ".h5"
                clf.save(path)
        print("Models Saved Successfully")

    def load(self, path=""):
        files = os.listdir(path)
        for i in files:

            if i.split(".")[-1] == "pickle":
                with open(path + i, "rb") as f:
                    self.trained.append(pickle.load(f))
            else:
                model = tf.keras.models.load_model(path + i)
                self.trained.append(model)
        return self


class CNN:
    def __init__(
        self, input=100, optimizer="adam", epochs=100, batch_size=64, window=5, lr=1e-2
    ):

        self.input = input
        self.optimizer = optimizer
        self.batch_size = batch_size
        self.epochs = epochs
        self.model = None
        self.window = window
        self.learning_rate = lr
        self.initialize()

    def initialize(self):

        inp = Input(shape=(self.input, 1))
        l1 = Conv1D(
            filters=32,
            kernel_size=6,
            strides=1,
            activation="relu",
            padding="valid",
            name="layer1",
        )(inp)

        l3 = tf.keras.layers.Reshape((32, 1), input_shape=(32,))(
            GlobalMaxPooling1D(name="layer3")(l1)
        )

        l4 = Conv1D(
            filters=64,
            kernel_size=6,
            strides=1,
            activation="relu",
            padding="valid",
            name="layer4",
        )(l3)

        l6 = GlobalMaxPooling1D(name="layer6")(l4)

        l7 = Dense(1024, name="layer7")(l6)

        l9 = Dense(25, name="layer9")(l7)

        l11 = Dense(1, name="layer11", activation="sigmoid")(l9)

        model = Model(
            inputs=[inp],
            outputs=[l11, l7],
        )

        print("Model Compiled", model)
        self.model = model

    def fit(self, x, y):

        xt, xval, yt, yval = train_test_split(
            x, y, stratify=y, random_state=42, test_size=0.2
        )

        train_dataset = tf.data.Dataset.from_tensor_slices((xt, yt))
        train_dataset = train_dataset.batch(self.batch_size)

        val_dataset = tf.data.Dataset.from_tensor_slices((xval, yval))
        val_dataset = val_dataset.batch(self.batch_size)

        epochs = self.epochs
        optimizer = tf.keras.optimizers.Adam(learning_rate=self.learning_rate)

        for epoch in range(epochs):
            print("\nStart of epoch %d" % (epoch,))
            loss_value = []

            for step, (x_batch_train, y_batch_train) in tqdm(enumerate(train_dataset)):

                with tf.GradientTape() as tape:

                    logits = self.model(x_batch_train, training=True)
                    self.model.compile()
                    loss = self.loss(y_batch_train, logits)

                    grads = tape.gradient(loss, self.model.trainable_weights)

                    optimizer.apply_gradients(zip(grads, self.model.trainable_weights))
                    loss_value.append((loss.numpy()))

            val_loss = []

            for s, (xv, yv) in enumerate(val_dataset):

                out = self.model(xv, training=False)
                self.model.compile()
                vloss = self.loss(yv, out)
                val_loss.append(vloss)

            print("Training loss for epoch {}: {}".format(epoch, np.mean(loss_value)))
            print("Validation loss for epoch {}: {}".format(epoch, np.mean(val_loss)))

        return self

    def validation(self):
        pass

    def predict(self, x, truelabels=None):

        y_pred, features = self.model.predict(x)

        y_pred = (y_pred > 0.5).astype(int)

        return y_pred, features

    def loss(self, y, logits):

        loss = tf.keras.losses.BinaryCrossentropy(reduction="none")(y, logits[0])

        return loss


class AutoEncoder(torch.nn.Module):
    def __init__(self, batch_size=64, epochs=100, lr=1e-3):
        super().__init__()
        self.batch_size = batch_size
        self.epochs = epochs
        self.learning_rate = lr
        self.losses = []
        self.threshold = None
        self.loss_fn = None
        self.optimizer = None
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(1024, 512),
            torch.nn.ReLU(),
            torch.nn.Linear(512, 256),
            torch.nn.ReLU(),
        )

        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(256, 512),
            torch.nn.ReLU(),
            torch.nn.Linear(512, 1024),
            torch.nn.LayerNorm(1024),
        )

    def forward(self, x):

        x = self.encoder(x)

        x = self.decoder(x)
        return x

    def fit(self, X, Y):

        X = torch.from_numpy(X[Y == 0])
        Y = torch.from_numpy(Y[Y == 0])

        X = X.type(torch.FloatTensor)
        Y = Y.type(torch.LongTensor)

        train = torch.utils.data.TensorDataset(X, Y)

        self.loss_fn = torch.nn.MSELoss()
        self.optimizer = torch.optim.Adam(self.parameters(), lr=self.learning_rate)

        for epoch in range(self.epochs):
            print("Training Epoch:{}".format(epoch))

            training_data = torch.utils.data.DataLoader(
                train, batch_size=self.batch_size, shuffle=True
            )

            temp = 0
            for i, data in enumerate(training_data):

                self.optimizer.zero_grad(set_to_none=True)

                x, y = data

                out = self(x)

                loss = self.loss_fn(x, out)
                loss.backward()
                self.optimizer.step()

                temp += torch.mean(loss)

            temp = temp / (i + 1)
            self.losses.append(temp.detach().numpy().item())

            print(
                "Loss with Batch {} of Epoch {} is {} ".format(
                    self.batch_size, epoch, temp
                )
            )

        print("Training Completed")

        self.find_threshold(X)

        print("The MSE threshold is : ", self.threshold)

        return self

    def find_threshold(self, X):

        with torch.no_grad():

            self.eval()

            rc = self(X)

            loss = torch.nn.MSELoss(reduction="none")(X, rc)

            print(loss.size())
            loss = torch.mean(loss, axis=1)
            print(loss.size())

        self.threshold = torch.quantile(loss, q=0.99).detach().numpy().item()
        self.threshold = (
            (torch.mean(loss) + 2 * torch.std(loss)).detach().numpy().item()
        )

    def predict(self, data):

        data = torch.from_numpy(data)
        data = data.type(torch.FloatTensor)

        self.eval()

        with torch.no_grad():

            predictions = self(data)

            pred_loss = torch.nn.MSELoss(reduction="none")(data, predictions)
            pred_loss = torch.mean(pred_loss, axis=1)

        ypred = (pred_loss.detach().numpy() > self.threshold).astype(int)

        return ypred

    def plot(self, file_path="AutoEncoder_Training"):

        plt.style.use("seaborn-poster")

        plt.figure()

        plt.plot(range(1, len(self.losses) + 1), self.losses, label="MSE", color="red")

        plt.xlabel("Epochs")
        plt.xlim(1, len(self.losses) + 10)
        plt.ylim(0, max(self.losses))

        plt.ylabel("Mean Squared Error")
        plt.rcParams.update({"font.size": 14})
        plt.legend(loc=1)
        plt.title(file_path)
        plt.show()

        plt.savefig(file_path + ".png", dpi=300)


class AE:
    def __init__(
        self, input, hlayers, output, optimizer="adam", epochs=100, batch_size=32
    ):
        super(AE, self).__init__()
        self.layers = hlayers
        self.input = input
        self.output = output
        self.optimizer = optimizer
        self.batch_size = batch_size
        self.epochs = epochs
        self.model = self.initialize()
        self.scaler = MinMaxScaler()
        self.pred_probab = None

    def initialize(self):

        model = Sequential()
        inp = Input(shape=(self.input,))
        model.add(inp)
        for i in self.layers:
            model.add(
                Dense(
                    i,
                    activation="relu",
                )
            )

        model.add(
            Dense(
                self.output,
                activation="sigmoid",
            )
        )

        model.compile(
            optimizer=self.optimizer,
            loss=tf.keras.losses.MeanSquaredError(),
            metrics=["mse"],
        )
        return model

    def fit(self, x, y):

        self.scaler = self.scaler.fit(x)
        x = self.scaler.transform(x)

        cb = EarlyStopping(monitor="val_loss", patience=10)

        hist = self.model.fit(
            x[y == 0],
            x[y == 0],
            batch_size=self.batch_size,
            epochs=self.epochs,
            verbose=1,
            callbacks=[cb],
            validation_split=0.2,
            shuffle=True,
            initial_epoch=0,
            validation_batch_size=self.batch_size,
            workers=-1,
        )

        self.threshold = self.find_threshold(x, y)
        print("MSE Threshold for Prediction is", self.threshold, type(self.threshold))
        return self

    def find_threshold(self, X, Y):

        X = self.scaler.fit_transform(X)
        reconstructions = self.model.predict(X)
        reconstruction_errors = tf.keras.losses.MeanSquaredError(reduction="none")(
            reconstructions, X
        )

        y_true = Y
        y_scores = reconstruction_errors
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)

        optimal_idx = np.argmax(tpr - fpr)
        optimal_threshold = thresholds[optimal_idx]
        print("Threshold value is:", optimal_threshold)

        return optimal_threshold

    def predict(self, x, truelabels=None):

        if not isinstance(x, np.ndarray):
            x = x.to_numpy()

        y_pred = self.model.predict(x)

        mse = tf.keras.losses.MeanSquaredError(reduction="none")(x, y_pred)

        self.pred_probab = mse.numpy()
        y_pred = (mse.numpy() > self.threshold).astype(int)
        return y_pred

    def save(self, path):
        self.model.save(path)


class neuralnetwork:
    def __init__(self, feature_dim, hidden_layers, output_layer, epochs=100, batch=32):
        self.input = feature_dim
        self.hidden_layers = hidden_layers
        self.output = output_layer
        self.activation = "relu"
        self.batch_size = batch
        self.epochs = epochs
        self.loss = "binary_crossentropy"
        self.model = self.initialize()
        self.verbose = 3

    def initialize(self):

        model = Sequential(name="NN_Classifier")
        model.add(Input(shape=(self.input,)))
        for i in self.hidden_layers:
            model.add(Dense(i, kernel_initializer="random_uniform", activation="relu"))
            model.add(BatchNormalization())

        model.add(
            Dense(self.output, kernel_initializer="random_normal", activation="sigmoid")
        )
        model.compile(
            optimizer="adam", loss="binary_crossentropy", metrics=[keras.metrics.AUC()]
        )
        return model

    def fit(self, X, Y):

        self.model.fit(
            X.astype(float),
            Y,
            batch_size=self.batch_size,
            verbose=self.verbose,
            epochs=self.epochs,
            callbacks=None,
            workers=-1,
        )
        return self

    def predict(self, xtest):
        y_pred = self.model.predict(xtest.astype(float))
        y_pred = (y_pred > 0.5).astype(int)
        return y_pred

    def save(self, path):
        self.model.save(path)


class SDAE:
    def __init__(
        self,
        n_visible=5,
        n_hidden=3,
        lr=0.001,
        corruption_level=0.0,
        gracePeriod=10000,
        hiddenRatio=None,
    ):

        self.n_visible = n_visible
        self.n_hidden = n_hidden
        self.lr = lr
        self.corruption_level = corruption_level
        self.gracePeriod = gracePeriod
        self.hiddenRatio = hiddenRatio
        if self.hiddenRatio is not None:
            self.n_hidden = int(numpy.ceil(self.n_visible * self.hiddenRatio))

        self.norm_max = numpy.ones((self.n_visible,)) * -numpy.Inf
        self.norm_min = numpy.ones((self.n_visible,)) * numpy.Inf
        self.n = 0

        self.rng = numpy.random.RandomState(1234)

        a = 1.0 / self.n_visible
        self.W = numpy.array(
            self.rng.uniform(low=-a, high=a, size=(self.n_visible, self.n_hidden))
        )

        self.hbias = numpy.zeros(self.n_hidden)
        self.vbias = numpy.zeros(self.n_visible)
        self.W_prime = self.W.T

    def get_corrupted_input(self, input, corruption_level):
        assert corruption_level < 1

        return self.rng.binomial(size=input.shape, n=1, p=1 - corruption_level) * input

    def get_hidden_values(self, input):
        return sigmoid(numpy.dot(input, self.W) + self.hbias)

    def get_reconstructed_input(self, hidden):
        return sigmoid(numpy.dot(hidden, self.W_prime) + self.vbias)

    def train(self, x):
        self.n = self.n + 1

        self.norm_max[x > self.norm_max] = x[x > self.norm_max]
        self.norm_min[x < self.norm_min] = x[x < self.norm_min]

        x = (x - self.norm_min) / (self.norm_max - self.norm_min + 0.0000000000000001)

        if self.corruption_level > 0.0:
            tilde_x = self.get_corrupted_input(x, self.corruption_level)
        else:
            tilde_x = x
        y = self.get_hidden_values(tilde_x)
        z = self.get_reconstructed_input(y)

        L_h2 = x - z
        L_h1 = numpy.dot(L_h2, self.W) * y * (1 - y)

        L_vbias = L_h2
        L_hbias = L_h1
        L_W = numpy.outer(tilde_x.T, L_h1) + numpy.outer(L_h2.T, y)

        self.W += self.lr * L_W
        self.hbias += self.lr * L_hbias
        self.vbias += self.lr * L_vbias
        return numpy.sqrt(numpy.mean(L_h2**2))

    def reconstruct(self, x):
        y = self.get_hidden_values(x)
        z = self.get_reconstructed_input(y)
        return z

    def execute(self, x):
        if self.n < self.gracePeriod:
            return 0.0
        else:

            x = (x - self.norm_min) / (
                self.norm_max - self.norm_min + 0.0000000000000001
            )
            z = self.reconstruct(x)
            rmse = numpy.sqrt(((x - z) ** 2).mean())
            return rmse

    def inGrace(self):
        return self.n < self.gracePeriod


class BNN:
    def __init__(self):
        pass


class KAE:
    def __init__(self, input, hidden_ratio=0.75, batch_size=1, epochs=100, mode=0):

        self.n = input
        self.B = hidden_ratio
        self.batch_size = batch_size
        self.epochs = epochs

        self.model = None
        self.optimizer = None
        self.loss_fn = tf.keras.losses.MeanSquaredError(reduction="none")

        self.losses = []

        self.hidden = int(self.B * self.n)

        if self.hidden == 0:
            self.hidden = 3

        self.mode = mode
        self.initialize()

    def initialize(self):

        inp = Input(shape=(self.n,), batch_size=self.batch_size)

        model = (Dense(self.n))(inp)

        model = (Dense(self.hidden))(model)

        out = (Dense(self.n, activation="sigmoid"))(model)

        self.model = Model(inputs=inp, outputs=[out])

        self.model.compile()

    def fit(self, x, y=None):

        self.optimizer = tf.keras.optimizers.Adam()

        with tf.GradientTape() as tape:

            out = self.model(x, training=True)
            self.model.compile()
            loss = self.loss_fn(x, out)

            gradient = tape.gradient(loss, self.model.trainable_weights)

            self.optimizer.apply_gradients(zip(gradient, self.model.trainable_weights))

            self.losses.append(loss)

        self.optimizer = None

        return loss

    def predict(self, x):

        out = self.model(x, training=False)
        self.model.compile()
        loss = self.loss_fn(x, out)

        return loss


class Kitsune_AE:
    def __init__(self, fmap=None, batch_size=1, epochs=1, B=0.75, lr=1e-3):

        self.ensemble = []
        self.outlayer = None
        self.fmap = fmap
        self.batch_size = batch_size
        self.epochs = epochs
        self.params = None
        self.B = B
        self.S1 = [0] * len(fmap)
        self.model = None
        self.learning_rate = lr
        self.mode = 0
        self.losses = []
        self.threshold = None
        self.optimizer = None
        self.loss_fn = None
        self.scaler = MinMaxScaler()
        self.val_losses = []
        if self.fmap == None:
            self.mode = 1

        self.initialize()

    def initialize(self):

        for fset in self.fmap:

            n = len(fset)

            temp = KAE(
                input=n,
                batch_size=self.batch_size,
                epochs=self.epochs,
                hidden_ratio=self.B,
            )

            self.ensemble.append(temp)

        hidden = int(len(self.S1) * self.B)

        inp = Input(
            shape=(
                len(
                    self.S1,
                )
            )
        )

        model = Dense(len(self.S1))(inp)

        model = Dense(hidden)(model)

        out = Dense(len(self.S1), activation="sigmoid")(model)

        self.model = Model(inputs=inp, outputs=[out])

        self.model.compile()

    def fit(self, X, Y):

        X = self.scaler.fit_transform(X)

        xt, xval, yt, yval = train_test_split(
            X, Y, stratify=Y, random_state=42, test_size=0.2
        )

        train_dataset = tf.data.Dataset.from_tensor_slices((xt[yt == 0], yt[yt == 0]))
        train_dataset = train_dataset.batch(self.batch_size)

        val_dataset = tf.data.Dataset.from_tensor_slices(
            (xval[yval == 0], yval[yval == 0])
        )
        val_dataset = val_dataset.batch(self.batch_size)

        self.optimizer = tf.keras.optimizers.Adam(learning_rate=self.learning_rate)
        self.loss_fn = tf.keras.losses.MeanSquaredError(reduction="none")
        c = 0
        vloss = []
        tl = 0
        vl = 0

        for epoch in range(self.epochs):

            self.val_losses = []

            print(
                "\n###########################Start of epoch########################### %d"
                % (epoch + 1,)
            )

            self.losses = []

            for step, (x, y) in tqdm(
                enumerate(train_dataset), desc="Epoch " + str(epoch + 1)
            ):

                self.S1 = self.stage(x, mode=self.mode)

                with tf.GradientTape() as tape:

                    output = self.model(self.S1, training=True)
                    self.model.compile()
                    loss = self.loss_fn(self.S1, output)
                    self.losses.extend(list(loss.numpy()))

                    grads = tape.gradient(loss, self.model.trainable_weights)
                    self.optimizer.apply_gradients(
                        zip(grads, self.model.trainable_weights)
                    )

            tl = np.mean(self.losses)
            print("Training Loss", tl)

        val_losses = []

        total_dataset = tf.data.Dataset.from_tensor_slices((X, Y))
        total_dataset = total_dataset.batch(self.batch_size)
        ytt = []
        for idx, (x, y) in enumerate(total_dataset):
            ytt.extend(list(y.numpy()))
            S1 = self.stage(x, mode=1)
            val_out = self.model(S1, training=False)
            self.model.compile()
            val_loss = self.loss_fn(S1, val_out)
            val_losses.extend(list(val_loss.numpy()))

        y_true = ytt
        y_scores = val_losses
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        optimal_idx = np.argmax(tpr - fpr)

        self.threshold = thresholds[optimal_idx]
        print("Threshold value is:", self.threshold)

        self.optimizer = None
        return self

    def stage(self, x, mode=0):

        S1 = [0] * len(self.fmap)

        for i in range(len(self.fmap)):

            feat = tf.gather(x, self.fmap[i], axis=1)

            if mode == 0:

                S1[i] = self.ensemble[i].fit(feat)
            else:
                S1[i] = self.ensemble[i].predict(feat)

        S1 = tf.stack(S1)
        S1 = tf.transpose(S1)
        return S1

    def predict(self, X, Y=None):

        X = self.scaler.fit_transform(X)
        self.mode = 1

        t_losses = []
        t_dataset = tf.data.Dataset.from_tensor_slices((X, np.zeros(X.shape[0])))
        t_dataset = t_dataset.batch(self.batch_size)

        for idx, (x, y) in enumerate(t_dataset):

            S1 = self.stage(x, mode=1)

            t_out = self.model(S1, training=False)

            t_loss = self.loss_fn(S1, t_out)
            t_losses.extend(list(t_loss.numpy()))

        ypred = (np.array(t_losses) > self.threshold * self.B).astype(int)

        return ypred


class GMM(GaussianMixture):
    def __init__(
        self, n_components=20, max_iter=1000, init_params="kmeans", verbose=2, tol=1e-5
    ):
        self.k = n_components
        self.n_components = n_components
        self.tol = tol
        self.max_iter = max_iter
        self.init_params = init_params
        self.verbose = verbose
        self.model = GaussianMixture(
            n_components=self.n_components,
            tol=self.tol,
            max_iter=self.max_iter,
            init_params=self.init_params,
            verbose=self.verbose,
        )
        self.threshold = 1 / best_k

    def fit(self, X, Y):
        print(X.shape, Y.shape)

        xt, xtest, yt, ytest = train_test_split(
            X, Y, test_size=0.2, stratify=Y, random_state=42
        )

        K = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]

        print("Training and tuning GMM")
        accuracy = 0
        best_k = 2
        for k in K:

            self.model = GaussianMixture(
                n_components=k,
                tol=self.tol,
                max_iter=self.max_iter,
                init_params=self.init_params,
                verbose=self.verbose,
            )
            model = self.model.fit(xt[yt == 0])

            ypred = model.predict_proba(xtest)
            print("prediction output")
            print(model.predict(xtest))
            ypred = ypred.max(axis=1)
            ypred = (ypred < 1 / k).astype(int)

            a = roc_auc_score(ytest, ypred)
            if a > accuracy:
                accuracy = a
                best_k = k

        self.model = GaussianMixture(
            n_components=best_k,
            tol=self.tol,
            max_iter=self.max_iter,
            init_params=self.init_params,
            verbose=self.verbose,
        )
        self.threshold = 1 / best_k

        print("Normal Instances are as follows", X[Y == 0].shape)
        self.model = self.model.fit(X[Y == 0], Y[Y == 0])
        return self

    def predict(self, X):

        y_pred = self.model.predict_proba(X)
        y_pred = (y_pred < self.threshold).astype(int)

        return y_pred.max(axis=1)

    def save(self, directory=""):
        path = directory + self.model.__class__.__name__ + ".pickle"
        with open(path, "wb") as f:
            pickle.dump(self.model, f)


class OCSVM_scaled:
    def __init__(self, kernel="linear", gamma="scale", shrinking=False, tol=1e-5):

        self.model = make_pipeline(
            StandardScaler(),
            OneClassSVM(
                gamma=gamma,
                verbose=3,
                kernel=kernel,
                cache_size=6000,
                shrinking=shrinking,
                tol=tol,
            ),
        )

    def fit(self, X, Y):
        print("Training OCSVM")
        self.model = self.model.fit(X[Y == 0], Y[Y == 0])
        print("Successfully Stored Trained OCSVM")
        return self

    def predict(self, X):
        y_pred = self.model.predict(X)
        y_pred[y_pred == 1] = 0
        y_pred = (y_pred < 0).astype(int)
        return y_pred

    def save(self, directory=""):
        path = directory + self.model.__class__.__name__ + ".pickle"
        with open(path, "wb") as f:
            pickle.dump(self, f)


class Isoforest:
    def __init__(
        self,
    ):
        self.model = IsolationForest(n_jobs=-1)

    def fit(self, X, Y):
        print("Training Isolation Forest")
        self.model = self.model.fit(X[Y == 0], Y[Y == 0])
        print("Successfully Stored Trained Isolation Forest")
        return self

    def predict(self, X):
        y_pred = self.model.predict(X)
        y_pred = (y_pred < 0).astype(int)
        return y_pred

    def save(self, directory=""):
        path = directory + self.model.__class__.__name__ + ".pickle"
        with open(path, "wb") as f:
            pickle.dump(self, f)


class OCSVM:
    def __init__(self, kernel="linear", gamma="scale", shrinking=False, tol=1e-5):
        self.model = OneClassSVM(
            gamma=gamma,
            verbose=3,
            kernel=kernel,
            cache_size=6000,
            shrinking=shrinking,
            tol=tol,
        )

    def fit(self, X, Y):
        print("Training OCSVM")
        self.model = self.model.fit(X[Y == 0], Y[Y == 0])
        print("Successfully Stored Trained OCSVM")
        return self

    def predict(self, X):
        y_pred = self.model.predict(X)
        y_pred[y_pred == 1] = 0
        y_pred = (y_pred < 0).astype(int)

        return y_pred

    def save(self, directory=""):
        path = directory + self.model.__class__.__name__ + ".pickle"
        with open(path, "wb") as f:
            pickle.dump(self, f)


class GRUModel:
    def __init__(self, hidden_layers, output_layer, epochs=100, batch=32, lookback=20):

        self.hl = hidden_layers
        self.output = output_layer
        self.activation = "relu"
        self.batch_size = batch
        self.epochs = epochs
        self.loss = "binary_crossentropy"
        self.model = None
        self.verbose = 3
        self.lookback = lookback

    def initialize(self, X_train):
        model = Sequential()
        model.add(
            GRU(
                X_train.shape[2],
                input_shape=(X_train.shape[1], X_train.shape[2]),
                return_sequences=True,
                activation="relu",
            )
        )

        for i in range(len(self.hl) - 1):
            model.add(GRU(self.hl[i], activation="relu", return_sequences=True))
        model.add(GRU(self.hl[-1], activation="relu"))

        model.add(Dense(self.output, activation="sigmoid"))
        model.compile(
            optimizer=tf.keras.optimizers.Adam(),
            loss="binary_crossentropy",
            metrics=["accuracy"],
        )
        self.model = model

    def create_dataset(self, X, Y):

        X_t, Y_t = [], []

        if len(Y) != 0:

            for i in range(self.lookback):
                X_t.append(np.zeros((self.lookback, X.shape[1])))
                Y_t.append(0)

            for i in range(self.lookback + 1, X.shape[0]):
                X_t.append(X[i - 1 - self.lookback : i - 1])
                Y_t.append(Y[i])

        else:

            for i in range(self.lookback):
                X_t.append(np.zeros((self.lookback, X.shape[1])))

            for i in range(self.lookback, X.shape[0]):
                X_t.append(X[i - self.lookback : i])

        X_t, Y_t, = np.asarray(X_t).astype(np.int), np.asarray(
            Y_t
        ).astype(np.int)

        return X_t, Y_t

    def fit(self, X, Y):

        X_train, Y_train = self.create_dataset(X, Y)
        self.initialize(X_train)

        earlystop = EarlyStopping(
            monitor="accuracy", min_delta=0.0001, patience=10, verbose=1, mode="min"
        )
        hist = History()
        callbacks_list = [earlystop, hist]

        self.model.fit(
            X_train,
            Y_train,
            batch_size=self.batch_size,
            verbose=self.verbose,
            epochs=self.epochs,
            validation_split=0.2,
            callbacks=callbacks_list,
            workers=-1,
        )

        print("Predictions on Training Dataset")
        print(self.model.predict(X_train))
        print(hist.history)
        return self

    def predict(self, xtest):
        Xt, Yt = self.create_dataset(xtest, [])

        y_pred = self.model.predict(Xt.astype(float))
        y_pred = (y_pred > 0.5).astype(int)
        return y_pred

    def load(self):
        pass

    def save(self, path):
        self.model.save(path)


class CNNAE:
    def __init__(self, input=100, epochs=10, batch_size=32):

        self.CNN = CNN(input=input, epochs=epochs, batch_size=batch_size)
        self.AE = AE(
            epochs=epochs,
            batch_size=batch_size,
            input=1024,
            output=1024,
            hlayers=[512, 256, 512],
        )
        self.scaler = MinMaxScaler()

    def fit(self, X, Y):

        X = self.scaler.fit_transform(X)

        self.CNN = self.CNN.fit(X, Y)

        classes, features = self.CNN.predict(X)

        features = self.scaler.fit_transform(features)

        self.AE = self.AE.fit(features, Y)

        return self

    def predict(self, Xt):
        Xt = self.scaler.fit_transform(Xt)
        classes, feat_test = self.CNN.predict(Xt)
        features = self.scaler.fit_transform(feat_test)
        ypred = self.AE.predict(feat_test)
        return ypred


class ANN:
    def __init__(
        self,
        hidden_layers,
        output_layer,
        epochs=100,
        batch=32,
    ):

        self.hl = hidden_layers
        self.output = output_layer
        self.activation = "relu"
        self.batch_size = batch
        self.epochs = epochs
        self.loss = "mse"
        self.model = None
        self.verbose = 3

    def initialize(self, X_train):
        model = Sequential()
        model.add(Input())

        for i in range(len(self.hl) - 1):

            model.add(
                Dense(
                    self.hl[i],
                    activation="relu",
                )
            )

        model.add(Dense(self.output))
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.1),
            loss="binary_crossentropy",
            metrics=["accuracy"],
        )
        self.model = model


class myord:
    def __init__(self, params={}):
        self.params = params
        self.model = OrdinalEncoder(
            handle_unknown="use_encoded_value", unknown_value=-1
        )

    def fit(self, X_train):
        X_train = X_train.astype(str)
        self.model.fit(X_train)
        return self

    def transform(self, X_train):
        X_train = X_train.astype(str)
        return self.model.transform(X_train)


class KJL:
    def __init__(
        self, params={"n": 100, "d": 5, "q": 0.9, "random_state": 42, "replace": False}
    ):
        self.params = params
        self.d = self.params["d"]
        self.n = self.params["n"]
        self.m = self.n
        self.q = self.params["q"]
        self.random_state = self.params["random_state"]
        self.verbose = 0
        self.sigma = None
        self.replace = params["replace"]

    def fit(self, X_train, y_train=None, X_train_raw=None, y_train_raw=None):
        N, D = X_train.shape

        if self.sigma is not None:

            self.sigma = self.sigma
        else:

            print()
            dists = pairwise_distances(X_train[0:10000])
            self.sigma = np.quantile(dists, self.q)
            print("Sigma is ", self.sigma)
            if self.sigma == 0:
                print(f"sigma:{self.sigma}, and use 1e-7 for the latter experiment.")
                self.sigma = 0.1

        np.random.seed(self.random_state)
        independent_row_col = 0
        if independent_row_col:
            indRow = resample(
                range(N),
                n_samples=self.n,
                random_state=self.random_state,
                stratify=y_train,
                replace=self.replace,
            )
            indCol = resample(
                range(N),
                n_samples=self.m,
                random_state=self.random_state,
                stratify=y_train,
                replace=self.replace,
            )
        else:
            indices = resample(
                range(N),
                n_samples=max(self.n, self.m),
                random_state=self.random_state,
                stratify=y_train,
                replace=self.replace,
            )
            indRow = indices[0 : self.n]
            indCol = indices[0 : self.m]
        Xrow = X_train[indRow, :]
        Xcol = X_train[indCol, :]

        A = getGaussianGram(Xrow, Xcol, self.sigma)
        self.uncenter_A = A

        centering = 1
        if centering:
            A = A - np.mean(A, axis=0)

        np.random.seed(self.random_state)
        self.random_matrix = np.random.multivariate_normal(
            [0] * self.d, np.diag([1] * self.d), self.m
        )
        self.U = np.matmul(A, self.random_matrix)
        self.Xrow = Xrow

        return self

    def transform(self, X):
        K = getGaussianGram(X, self.Xrow, self.sigma)
        X = np.matmul(K, self.U)
        return X


class Nystrom:
    def __init__(
        self,
        params={"n": 200, "d": 5, "q": 0.9, "random_state": 42, "replace": False},
        debug=False,
        verbose=1,
    ):
        self.nystrom_params = params
        self.random_state = params["random_state"]
        self.debug = debug
        self.verbose = verbose
        self.replace = params["replace"]

    def fit(self, X_train, y_train=None):

        d = self.nystrom_params["d"]
        n = self.nystrom_params["n"]
        q = self.nystrom_params["q"]
        N, D = X_train.shape

        if hasattr(self, "sigma") and self.sigma:
            self.sigma = self.sigma
        else:
            dists = pairwise_distances(X_train[0:10000])

            print(dists.shape)
            self.sigma = np.quantile(dists, q)
            print(self.sigma)
            if self.sigma == 0:
                self.sigma = 0.1
        m = n
        np.random.seed(self.random_state)

        independent_row_col = 0
        if independent_row_col:

            indRow = resample(
                range(N),
                n_samples=n,
                random_state=self.random_state,
                stratify=y_train,
                replace=self.replace,
            )
            indCol = resample(
                range(N),
                n_samples=m,
                random_state=self.random_state,
                stratify=y_train,
                replace=self.replace,
            )
        else:
            indices = resample(
                range(N),
                n_samples=max(n, m),
                random_state=self.random_state,
                stratify=y_train,
                replace=self.replace,
            )
            indRow = indices[0:n]
            indCol = indices[0:m]
        Xrow = X_train[indRow, :]
        Xcol = X_train[indCol, :]

        Ksub = getGaussianGram(Xrow, Xcol, self.sigma)
        print(Ksub.shape)

        try:
            Lambda, Eigvec = scipy.sparse.linalg.eigs(
                Ksub, k=d, which="LM", v0=np.ones(Ksub.shape[0])
            )
        except Exception as e:
            print(
                f"scipy.sparse.linalg.eigs error, {e}, try to add 1e-3 to redo again or lower accuracy"
            )
            Lambda, Eigvec = scipy.sparse.linalg.eigs(
                Ksub, k=d, which="LM", v0=np.ones(Ksub.shape[0]), tol=1e-10
            )
        self.Lambda = np.real(np.diag(Lambda))
        self.Eigvec = np.real(Eigvec)
        self.Xrow = Xrow
        self.eigvec_lambda = np.matmul(
            self.Eigvec, np.diag(1.0 / np.sqrt(np.diag(self.Lambda)))
        )
        return self

    def transform(self, X):
        K = getGaussianGram(X, self.Xrow, self.sigma)
        X = np.matmul(K, self.eigvec_lambda)
        return X


class CorrelationFilter:
    def __init__(self, threshold=0.1, count=None, path=""):
        self.threshold = threshold
        self.count = count
        self.columns = None
        pass

    def fit_transform(self, data):

        corr = data.corr()
        columns = np.full((corr.shape[0],), True, dtype=bool)

        for i in range(corr.shape[0]):
            for j in range(i + 1, corr.shape[0]):
                if corr.iloc[i, j] >= self.threshold:
                    if columns[j]:
                        columns[j] = False
        selected_columns = data.columns[columns]
        data = data[selected_columns]
        self.columns = data.columns

        return data

    def save(self, path):

        with open(path + "/selection.pickle", "wb") as f:
            pickle.dump(self.columns)


class binning:
    def init(self, bins="quantile"):
        self.bins = bins
        pass

    def transform(self):
        pass


functionlist = {
    "header_extract": header_extract,
    "header_extract_flow": header_extract_flow,
    "zeek_extract": zeek_extract,
    "tcptrace_extract": tcptrace_extract,
    "timeslicer": timeslicer,
    "timeslicer2": timeslicer2,
    "timeslicer_map": timeslicer_map,
    "aggregates2": aggregates2,
    "create_feature": create_feature,
    "debugger": debugger,
    "maptopacket": maptopacket,
    "bidir": bidir,
    "direction": direction,
    "direction1": direction1,
    "join2": join2,
    "keep_FE": keep_FE,
    "feature_elim": feature_elim,
    "flowbuilder": flowbuilder,
    "flowbuilder_map": flowbuilder_map,
    "flow_label": flow_label,
    "applytransform": applytransform,
    "packet_direction": packet_direction,
    "join": join,
    "clean": clean,
    "impute": impute,
    "flow_select": flow_select,
    "concatenate": concatenate,
    "transforms": transforms,
    "aggregates": aggregates,
    "agg2D": agg2D,
    "model": model,
    "train": train,
    "test": test,
    "nprint_features": nprint_features,
    "wireshark_features": wireshark_features,
    "kitsune_features": fe_kitsune,
    "weights_kitsune": weights_kitsune,
    "magnitude": magnitude,
    "radius": radius,
    "cov": cov,
    "pcc": pcc,
    "rtt": rtt,
    "meanflow": meanflow,
    "truncate": truncate,
    "bandwidth": bandwidth,
    "cardinality": cardinality,
    "nprotocols": nprotocols,
    "novelty": novelty,
    "is_TCP": isTCP,
    "is_HTTP": isHTTP,
    "is_UDP": isUDP,
    "is_OTHER": isOTHER,
    "sport": sport,
    "dport": dport,
    "IAT": IAT,
    "DFT": DFT,
    "dIAT": dIAT,
    "ddIAT": ddIAT,
    "mean": mean,
    "median": median,
    "Min": Min,
    "Max": Max,
    "std": std,
    "size_vector": size_vector,
    "var": var,
    "norm100": norm100,
    "count": count,
    "ploss": ploss,
    "total_loss": total_loss,
    "tbytes": tbytes,
    "packet_rate": packet_rate,
    "Bin": Bin,
    "quantile": quantile,
    "entropy2": entropy2,
    "coeffofvar": coeffofvar,
    "cqv": cqv,
    "rateofchange": rateofchange,
    "flows": flows,
    "npackets": npackets,
    "Sum": Sum,
    "tcpsyns": tcpsyns,
    "tcpsynacks": tcpsynacks,
    "tcpacks": tcpacks,
    "flagtype": flagtype,
    "bin_index": bin_index,
    "protocols": protocols,
    "flow_duration": duration,
    "index": index,
    "KJL": KJL,
    "Nystrom": Nystrom,
    "Normalizer": Normalizer,
    "minmaxscaler": MinMaxScaler,
    "StandardScaler": StandardScaler,
    "myord": myord,
    "clustering": clustering,
    "Ensemble": Ensemble,
    "Brute": Brute,
    "GMM": GMM,
    "NN": neuralnetwork,
    "OCSVM": OCSVM,
    "OCSVM_scaled": OCSVM_scaled,
    "Isoforest": Isoforest,
    "LOF": LocalOutlierFactor,
    "GRU": GRUModel,
    "RandomForest": RandomForestClassifier,
    "Knn": KNeighborsClassifier,
    "DT": DecisionTreeClassifier,
    "SVC": SVC,
    "RayXGBClassifier": RayXGBClassifier,
    "Kmeans": KMeans,
    "Kitsune_AE": Kitsune_AE,
    "AE": AE,
    "CNN": CNN,
    "CNNAE": CNNAE,
    "save_row": save_row,
    "AutoML": AutoML,
    "NaiveBayes": GaussianNB,
    "XGBClassifier": XGBClassifier,
    "Adaboost": AdaBoostClassifier,
    "CorrelationFilter": CorrelationFilter,
    "select": select,
    "trim": trim,
    "LabelEncoder": LabelEncoder,
    "OrdinalEncoder": OrdinalEncoder,
    "OHE": OneHotEncoder,
    "metrics": metrics,
}
