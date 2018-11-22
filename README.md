# checkSURBL

## This is a test.
因为部分邮件服务器会使用Spam URL Realtime blocklists（SURBL）对垃圾邮件进行检测。邮件服务器会主动向SURBL发起DNS询问，其特征是domain: *.multi.surbl.org。
因此检测流量中DNS的请求回答。步骤：<br>
```
1）根据回答判断域名是否存在威胁，其answer字段会表明SURBL的检测结果。<br>
2）并联合xforce对域名进行检测，获取xforce的相关评分以及信息。<br>
3）发出告警，告警信息导入ES。<br>
```
### SURBL相关信息查看：https://blog.csdn.net/max_ss/article/details/84334972