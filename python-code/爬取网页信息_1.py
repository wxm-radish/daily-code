#coding:utf-8
import requests
# import time
from bs4 import BeautifulSoup
url = "http://xiaoyillq.xyz/abc/JD.htm"
r = requests.get(url)
bs_1 = BeautifulSoup(r.content,'lxml')

for x in range(1,58):
    a = bs_1.find_all(name='div',attrs={"class":"col-33"})[x].find_all(name='div',attrs={"class":"catbloc"})[0].string
    a = a.replace('\r','')
    a = a.replace('\n','')
    a = a.replace(' ','')
    print a,bs_1.find_all(name='div',attrs={"class":"col-33"})[x].find_all('a')[0].get("href")
# print bs_1.find_all(name='div',attrs={"class":"col-33"})[1].find_all('script')


'''
电脑注册 https://reg.jd.com/reg/person
手机注册 https://plogin.m.jd.com/mreg/index
个人中心 https://home.m.jd.com/myJd/newhome.action
强制换绑 https://msc.jd.com/phone/loginpage/wcoo/index
强改地址 http://xiaoyillq.top/qgdz.html
JD检测 https://www.csfaka.com/links/A0031863
我的红包 https://wqs.jd.com/my/redpacket.shtml
优惠卷 https://wqs.jd.com/my/coupon/index.shtml
京喜首页 https://wq.jd.com/mcoss/wxmall/home
我的订单 https://wqs.jd.com/order/orderlist_merge.shtml
我的地址 https://wqs.jd.com/my/my_address.shtml
京东首页 https://u.jd.com/UYdyAS
我的购物车 https://wqdeal.jd.com/deal/mshopcart/mycart
银行卡解绑 https://msc.jd.com/card/loginpage/wcoo/getBindList
-5商品 https://u.jd.com/Vg4HDA
新人专属 https://u.jd.com/agSH2U
极速新人 https://u.jd.com/5zPWOR
新人超市 https://u.jd.com/408RNp
新人一分购 https://u.jd.com/MbcQoU
新人1元购 https://u.jd.com/y7G7PG
新人补贴 https://u.jd.com/bkBSQ7
新人优惠购 https://u.jd.com/K4ShDu
3元红包 https://u.jd.com/oeaYKX
新人数码 https://u.jd.com/991oYV
288大礼包 https://u.jd.com/k7QbUS
新人二维码 http://note.youdao.com/noteshare
京喜9.9-8 https://u.jd.com/Nqn3rA
19-3话费券 https://u.jd.com/vsISkr
49-3话费券 https://u.jd.com/8DGOUE
极速9.9-9 https://u.jd.com/2NxGTo
天降福利 https://funearth.m.jd.com/babelDiy/APBZGANYNZJPQXJJEFQX/8zF4D6VX5RhsBFxkmLV7WXNk6iQ/index.html
老188 https://u.jd.com/RSntxv
新188 https://u.jd.com/rSKvSl
新食力燥起来 https://u.jd.com/SCskn7
新人生鲜区 https://u.jd.com/07QzK8
79-20牛奶 https://u.jd.com/fmeCd1
快递大礼包 https://u.jd.com/BwLE5R
校园优惠 https://u.jd.com/XRwkmM
食饮低价好物 https://u.jd.com/fy8xdM
店铺9-9 https://u.jd.com/aKwi9m
9.9-8券 https://u.jd.com/rcWdaJ
9.9-5券 https://u.jd.com/oT7mRi
话费订单 https://u.jd.com/paYJNL
校园认证  https://student-certi.jd.com/#/
10-3话费券 https://coupon.m.jd.com/coupons/show.action
充值缴费 hhttps://newcz.m.jd.com/
6支付卷 https://u.jd.com/q3J1wR
京喜赚金币 https://wqsh.jd.com/pingou/taskcenter/index.html
话费直冲 https://wqs.jd.com/wxsq_project/recharge/pingou/pingou.html
一元礼盒① https://u.jd.com/8O78dZ
【一元多单】 https://u.jd.com/xquvMB
一元购① https://u.jd.com/n6y6u7
一元购② https://u.jd.com/tnBMc2
一元购③ https://u.jd.com/t7QL6d
设置密码 https://sec.m.jd.com/todo/editPassword
支付密码 https://wqs.jd.com/my/payPasswordManage.shtml
号归属地 http://m.ip138.com/mobile.asp
'''