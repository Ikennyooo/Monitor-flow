from flask import Flask, render_template, request

from scapy.all import *
from pyecharts import options as opts
from pyecharts.charts import Bar


app = Flask(__name__)


@app.route('/')

def index():

    return render_template("odk.html")

@app.route('/ikk',methods=['post'])

def main():

    # 读取数据！！
    dpkt = rdpcap(r"C:\Users\29080\Desktop\ikzhuabao3.pcap")

    # 定义一下
    k1 = int(request.form.get("frequency"))
    k2 = int(request.form.get("packet"))

    # 创建用于计算包数所用的变量们 ~~
    cnt1 = 0  #
    cnt2 = 0  #
    cnt3 = 0  #
    cnt4 = 0  #
    cnt7788 = 0  # 次数

    # 创建用于计算包长所用的变量们 ~~

    len1 = 0  #
    len2 = 0  #
    len3 = 0  #
    len4 = 0  #

    # 创建列表们 用于作图！

    chang = [0]  # 包长（顾名思义chang）
    shu = [0]    # 包数（顾名思义shu哈哈哈哈哈哈哈）

    # 分别创建空的字典，保存一个五元组的流量和总长度
    dic1 = {}   # 长度
    dic2 = {}   # 次数

    # 遍历获得数据
    for cnt in range(len(dpkt)):
        # 循环次数计数cnt7788
        cnt7788 += 1

        # 如果说不是IP协议的就pass 2048代表IP协议
        if dpkt[cnt][Ether].type != 2048:
            continue

        # 如果不是TCP和UDP就pass
        if dpkt[cnt][IP].proto != 6 and dpkt[cnt][IP].proto != 17:
            continue

        # 获得协议类型proto，6是TCP，17是UDP
        if dpkt[cnt][IP].proto == 6:
            proto = "TCP"
        if dpkt[cnt][IP].proto == 17:
            proto = "UDP"

        # 获得IP地址
        ip_src = dpkt[cnt][IP].src
        ip_dst = dpkt[cnt][IP].dst

        # 获得相关端口
        sport = dpkt[cnt][proto].sport
        dport = dpkt[cnt][proto].dport

        # 获取这个包的长度
        length = len(dpkt[cnt])
        # 格式
        tup = (ip_src, sport, ip_dst, dport, proto)

        # 获得并计算，提取相关数据dic1、dic2以用于html
        getting = dic1.get(tup,0)
        dic1[tup] = getting + length  # 总长度+该包的长度
        dic2[tup] = getting + 1       # 次数+1

        # 计算10K~100K的包长&包数相关数据，以用于html
        cnt1 += 1
        len1 += length
        if cnt7788 % 10000 == 0:
            cnt2 += 1
            chang.append(len1)
            shu.append(cnt1)
        else:
            chang[cnt2] = len1
            shu[cnt2] = cnt1

    # html相关，Echart.min.js下的柱状图模板，将chang的数据带给柱状图。
    bar = (
        Bar()
            .add_xaxis(["10K","20K","30K","40K","50K","60K","70K","80K","90K","100K"])

            .add_yaxis("length", [chang[0],chang[1],chang[2],chang[3],chang[4],chang[5],chang[6],chang[7],chang[8],chang[9]])

            .set_global_opts(title_opts=opts.TitleOpts(title="流量监控", subtitle="包长"))
    )
    # 带变量、device给美丽html
    return render_template('beautiful.html', k1=k1, k2=k2, dic1=dic1, dic2=dic2,
                           bar_options=bar.dump_options())


if __name__ == "__main__":

    app.run(debug = True)
