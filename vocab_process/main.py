#-*- coding:utf-8 -*-

# 导入必要的模块
import json  # 用于处理JSON格式数据
import os  # 提供与操作系统相关的功能
import random  # 生成伪随机数

import binascii  # 用于二进制和ASCII之间的转换
import scapy.all as scapy  # Scapy库，用于网络数据包的处理
from flowcontainer.extractor import extract  # 从流量中提取信息的自定义模块
from tokenizers import (  # 用于自然语言处理的tokenizers库
    Tokenizer,
    models,
    pre_tokenizers,
    decoders,
    trainers,
    processors,
)

# 设置随机数生成器的种子，以确保随机性可重复
random.seed(40)
# 定义PCAP文件的目录路径
pcap_dir = "I:\\dataset\\"
# 定义TLS日期范围，用于筛选流量数据
tls_date = [20210301, 20210808]
# 定义PCAP文件的名称，可以切换注释以选择不同的PCAP文件
pcap_name = "app_A.pcap"
# pcap_name = "merge.pcap"
# 定义文本文件的目录路径，用于存储一些加密的TLS13流量数据
word_dir = "/root/sda2/lx-project/models/ET-Bert-data/corpora/"
# 定义文本文件的名称，存储加密的TLS13流量数据
# word_name = "encrypted_tls13_burst.txt"
word_name = "encrypted_traffic_burst.txt"
# 定义词汇文件的目录路径，用于存储生成的词汇表
vocab_dir = "I:/models/"
# 定义词汇文件的名称，存储生成的词汇表
vocab_name = "encryptd_vocab_all.txt"
tls13_pcap_dir = ''
tls13_name = ''

def pcap_preprocess():
    # 获取TLS日期范围的起始日期和结束日期
    start_date = tls_date[0]
    end_date = tls_date[1]
    # 初始化数据包数量
    packet_num = 0
    # 遍历日期范围内的每一天
    while start_date <= end_date:
        # 构建该日期的数据目录路径
        data_dir = tls13_pcap_dir + str(start_date) + "\\"
        # 调用预处理函数，获取该日期的数据包数量
        p_num = preprocess(data_dir)
        # 累加数据包数量
        packet_num += p_num
        # 增加日期，继续下一天的处理
        start_date += 1
    # 打印总共使用的数据包数量
    print("used packets %d" % packet_num)
    # 打印处理完成的消息和结果存储路径
    print("finish generating tls13 pretrain dataset.\n please check in %s" % word_dir)
    # 返回0，表示预处理完成
    return 0

def preprocess(pcap_dir):
    # 打印当前正在处理的PCAP目录路径
    print("now pre-process pcap_dir is %s" % pcap_dir)
    # 初始化数据包数量和计数器
    packet_num = 0
    n = 0
    # 遍历目录下的文件和子目录
    for parent, dirs, files in os.walk(pcap_dir):
        for file in files:
            # 判断文件是否为指定格式的PCAP文件
            if "pcapng" not in file and tls13_name in file:
                # 记录已处理的PCAP文件数量
                n += 1
                # 构建完整的PCAP文件路径
                pcap_name = parent + "\\" + file
                print("No.%d pacp is processed ... %s ..." % (n, file))
                # 读取PCAP文件中的数据包
                packets = scapy.rdpcap(pcap_name)
                # 初始化存储单词的列表
                words_txt = []
                # 遍历每个数据包
                for p in packets:
                    packet_num += 1
                    # 复制数据包以避免修改原始数据
                    word_packet = p.copy()
                    # 将数据包转换为十六进制字符串
                    words = (binascii.hexlify(bytes(word_packet)))
                    # 从第77个字符开始提取十六进制字符串，避免包含PCAP头信息
                    words_string = words.decode()[76:]
                    # 获取字符串长度
                    length = len(words_string)
                    # 如果长度小于10，跳过当前数据包
                    if length < 10:
                        continue
                    # 切割字符串为单词，并生成bigram
                    for string_txt in cut(words_string, int(length / 2)):
                        token_count = 0
                        sentence = cut(string_txt, 1)
                        # 遍历每个bigram
                        for sub_string_index in range(len(sentence)):
                            if sub_string_index != (len(sentence) - 1):
                                token_count += 1
                                # 如果bigram数量超过256，跳出循环
                                if token_count > 256:
                                    break
                                else:
                                    merge_word_bigram = sentence[sub_string_index] + sentence[sub_string_index + 1]
                            else:
                                break
                            # 将bigram添加到单词列表
                            words_txt.append(merge_word_bigram)
                            words_txt.append(' ')
                        # 添加换行符表示新的数据包
                        words_txt.append("\n")
                    # 添加额外的换行符表示数据包之间的间隔
                    words_txt.append("\n")
                # 打开结果文件，将处理好的单词写入文件
                result_file = open(word_dir + word_name, 'a')
                for words in words_txt:
                    result_file.write(words)
                result_file.close()
    # 打印预处理完成的消息和已处理的PCAP文件数量
    print("finish preprocessing %d pcaps" % n)
    # 返回数据包数量
    return packet_num


def cut(obj, sec):
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    remanent_count = len(result[0])%4
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

def build_BPE():
    # 生成源字典，包含0到65535的16进制数
    num_count = 65536
    not_change_string_count = 5
    i = 0
    source_dictionary = {}
    tuple_sep = ()
    tuple_cls = ()
    # 'PAD':0,'UNK':1,'CLS':2,'SEP':3,'MASK':4
    while i < num_count:
        # 循环：当i小于num_count时执行以下操作
        # 将整数i转换为4位16进制字符串，并将其添加到源字典中
        temp_string = '{:04x}'.format(i)
        source_dictionary[temp_string] = i
        # 增加i的值，进行下一轮循环
        i += 1
    # 创建Tokenizer对象，使用WordPiece模型，并设置相关参数
    tokenizer = Tokenizer(models.WordPiece(vocab=source_dictionary, unk_token="[UNK]", max_input_chars_per_word=4))
    # 设置预处理器为BertPreTokenizer
    tokenizer.pre_tokenizer = pre_tokenizers.BertPreTokenizer()
    # 设置解码器为WordPiece
    tokenizer.decoder = decoders.WordPiece()
    # 设置后处理器为BertProcessing，指定分隔符和特殊标记
    tokenizer.post_processor = processors.BertProcessing(sep=("[SEP]", 1), cls=('[CLS]', 2))
    # 创建WordPieceTrainer对象，设置词汇表大小和最小词频
    trainer = trainers.WordPieceTrainer(vocab_size=65536, min_frequency=2)
    # 使用训练集进行训练，指定文件路径
    tokenizer.train([word_dir + word_name, word_dir + word_name], trainer=trainer)
    # 保存训练好的Tokenizer模型为JSON文件，可读性优化
    tokenizer.save("wordpiece.tokenizer.json", pretty=True)

    return 0

def build_vocab():
    json_file = open("wordpiece.tokenizer.json",'r')
    json_content = json_file.read()
    json_file.close()
    vocab_json = json.loads(json_content)
    vocab_txt = ["[PAD]","[SEP]","[CLS]","[UNK]","[MASK]"]
    for item in vocab_json['model']['vocab']:
        vocab_txt.append(item) # append key of vocab_json
    with open(vocab_dir+vocab_name,'w') as f:
        for word in vocab_txt:
            f.write(word+"\n")
    return 0

def bigram_generation(packet_string,flag=False):
    result = ''
    sentence = cut(packet_string,1)
    token_count = 0
    for sub_string_index in range(len(sentence)):
        if sub_string_index != (len(sentence) - 1):
            token_count += 1
            if token_count > 256:
                break
            else:
                merge_word_bigram = sentence[sub_string_index] + sentence[sub_string_index + 1]
        else:
            break
        result += merge_word_bigram
        result += ' '
    if flag == True:
        result = result.rstrip()

    return result

def read_pcap_feature(pcap_file):
    packet_length_feature = []
    feature_result = extract(pcap_file, filter='tcp')
    for key in feature_result.keys():
        value = feature_result[key]
        packet_length_feature.append(value.ip_lengths)
    return packet_length_feature[0]

def read_pcap_flow(pcap_file):
    packets = scapy.rdpcap(pcap_file)

    packet_count = 0
    flow_data_string = ''

    if len(packets) < 5:
        print("preprocess flow %s but this flow has less than 5 packets."%pcap_file)
        return -1

    print("preprocess flow %s" % pcap_file)
    for packet in packets:
        packet_count += 1
        if packet_count == 5:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()
            flow_data_string += bigram_generation(packet_string,flag = True)
            break
        else:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()
            flow_data_string += bigram_generation(packet_string)
    return flow_data_string

def split_cap(pcap_file,pcap_name):
    cmd = "I:\\SplitCap.exe -r %s -s session -o I:\\split_pcaps\\" + pcap_name
    command = cmd%pcap_file
    os.system(command)
    return 0

if __name__ == '__main__':
    # 如果作为主程序运行
    # 构建BPE分词模型
    build_BPE()
    # 构建词汇表
    # build_vocab()
    # 预处理PCAP数据
    # preprocess(pcap_dir)

