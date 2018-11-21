#!/usr/bin/python
# -*- coding:utf8 -*-
# @Time    : 2018/11/21 10:50
# @Author  : songh
# @File    : my_tools.py
# @Software: PyCharm
# all functions are implemented in this file.
import json,os,time,datetime
import check_XForce as xf

# read configuration file
def get_json(file):
    with open(file,'r') as fp:
        conf_data=json.load(fp)
    return conf_data

#======== pre read conf===============
fpath=os.getcwd()
files=fpath+os.path.sep+"config.json"
__conf_dt__=get_json(files)

# 清洗 dns的数据
def clean_dns_data(dataset):
    pass


# 获取 conf文件 启动时间
def get_starttime():
    tmp=__conf_dt__["time"]["start"]
    starttime=datetime.datetime.now()
    if(tmp is not "now"):
        starttime=datetime.datetime.strptime(tmp, '%Y-%m-%d %H:%M:%S')
    return starttime

def get_es_server():
    isvr=__conf_dt__["es_server"]
    iserver=isvr["server"]
    iport=isvr["port"]
    alert_indx=isvr["alert_index"]
    data_indx=isvr["data_index"]
    return iserver,iport,alert_indx,data_indx

def clean_dns_data(dataset):
    all_data=[]
    for dic in dataset:
        domain=dic["_source"]["domain"]
        answer=dic["_source"]["answer"]
        all_data.append([domain,answer])
    return all_data


def rebuild_alert_info(domain,answer,xfinfo,ansinfo):
    # info alert 模板
    doc={}
    doc["@timestamp"]=datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')
    doc["domain"]=domain
    doc["answer"]=answer
    doc["type"]="mal_dns"
    doc["subtype"]="surbl"
    doc["desc_type"]="[mal_dns] Request of Malicious Domain Name Detection"
    lis_str=','.join(ansinfo)
    doc["desc_subtype"]="[spam] The suspect domain has been listed on {0} by surbl".format(lis_str)
    doc["level"]="info"
    # xforce message
    try:
        cats=xfinfo[domain]["cats"]
        cats_lis=cats.keys()
        cats_str=','.join(cats_lis)
        doc["xforce_msg"]="cats:"+cats_str
    except Exception, e:
        doc["xforce_msg"]=None
    try:
        doc["xforce_marks"]=int(xfinfo[domain]["score"])
    except Exception,e:
        doc["xforce_marks"] = 0
    return doc

'''
step1:check xforce
step2:check answer
step3:rebuild the alert info
'''
def analyse_info(data):
    docs=[]
    for ii in data:
        domain=ii[0]
        answer=ii[1]
        # check domain
        xf_info=xf.start(2,[domain])
        # check answer
        last_one=int(answer.split('.')[-1])
        ans_info=[]
        if (last_one & 8):
            ans_info.append("PH")
        if (last_one & 16):
            ans_info.append("MW")
        if (last_one & 64):
            ans_info.append("ABUSE")
        if (last_one & 128):
            ans_info.append("CR")
        # get alert info, doc is dict
        doc=rebuild_alert_info(domain,answer,xf_info,ans_info)
        docs.append(doc)
    return docs


def insert_alert(es,docs,alert_idx):
    for doc in docs:
        es.es_index(doc,alert_idx)