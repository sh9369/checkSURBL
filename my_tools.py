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
    time_info=__conf_dt__["time"]
    tmp=time_info["start"]
    starttime=datetime.datetime.now()
    if(not(tmp == "now")):
        starttime=datetime.datetime.strptime(tmp, '%Y-%m-%d %H:%M:%S')
    # get interval
    intv=time_info["interval"]
    unit=intv[-1].lower()
    nums=int(intv[:-1])
    if(unit=="s"):
        deltatime = datetime.timedelta(seconds=nums)
    elif(unit == "m"):
        deltatime = datetime.timedelta(minutes=nums)
    elif(unit=="h"):
        deltatime = datetime.timedelta(hours=nums)
    elif(unit=='d'):
        deltatime = datetime.timedelta(days=nums)
    else:# by default
        deltatime = datetime.timedelta(days=1)
    return starttime,deltatime

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
        tmp=dic["_source"]["domain"]
        domain=tmp.split(".multi.")[0]
        answer=dic["_source"]["answer"]
        all_data.append([domain,answer])
    return all_data


def rebuild_alert_info(domain,answer,xfinfo,ansinfo):
    # info alert 模板
    doc={}
    # timestamp 构造与 starttime 不一样
    doc["@timestamp"]=datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%dT%H:%M:%S')+".000+08:00"
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
        doc["xforce_marks"]=int(xfinfo[domain]["score"])
    except Exception,e:
        print("error:{0}".format(e))
        print json.dumps(xfinfo)
        doc["xforce_marks"] = 0

    try:
        if(doc["xforce_marks"] == 0):
            doc["xforce_msg"] = None
        else:
            cats=xfinfo[domain]["cats"]
            cats_lis=cats.keys()
            cats_str=','.join(cats_lis)
            doc["xforce_msg"]="cats:"+cats_str
    except Exception, e:
        print("error:{0}".format(e))
        print json.dumps(xfinfo)
        doc["xforce_msg"]=None

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
        print("check xforce...")
        time.sleep(0.5)
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
        print("rebuild data ...")
        doc=rebuild_alert_info(domain,answer,xf_info,ans_info)
        docs.append(doc)
    return docs


def insert_alert(es,docs,alert_idx):
    for doc in docs:
        es.es_index(doc,alert_idx)