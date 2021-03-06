#!/usr/bin/python
# -*- coding:utf8 -*-
# @Time    : 2018/11/21 10:40
# @Author  : songh
# @File    : main.py
# @Software: PyCharm
import datetime,time
import my_tools,check_dns

'''
surbl_run() 检查函数入口
调用check_dns文件进行检查
'''
def surbl_run(starttime,delta):
    time_zone = ''
    if (time.daylight == 0):  # 1:dst;
        time_zone = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    else:
        time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
    check_dns.check_start(starttime,delta,time_zone)


'''
surbl_run() 主运行函数
step1: 获取启动时间；未达到时间则休眠；达到则运行step2
step2: 调用检查函数

'''
def main():
    stime,detaltime=my_tools.get_starttime()
    while(True):
        if stime>datetime.datetime.now():
            print("time sleep...")
            time.sleep((stime-datetime.datetime.now()).total_seconds())
        else:
            try:
                print("start surbl check...")
                surbl_run(stime,detaltime)
            except Exception,e:
                print("error:{0}".format(e))
            #detaltime=datetime.timedelta(days=1)
            stime=stime+detaltime

if __name__ == '__main__':
    main()