import os
import pymysql
import shutil
from my_print import print_log

def get_file_ext(filename):
    ext = filename.split(".")[1]
    return ext
def get_file_md5(path):
    cmd_res = os.popen("md5 "+path).read()
    file_md5 = cmd_res.split(" = ")[1]
    return file_md5.replace("\n","")

db = pymysql.connect(host = 'localhost',user = 'root',password = '123456',db = 'webshell',charset = 'utf8')
print_log("[*]connect mysql success")


cursor = db.cursor()

# 获取all 下面所有的文件
all_file = os.listdir("./all")


#去除.DS_Store
for x in range(len(all_file)):
    if all_file[x]==".DS_Store":
        all_file.pop(x)
        break

print(len(all_file))
file_idx = 2543
for x in range(len(all_file)):
    webshell_id = file_idx+x
    webshell_name = all_file[x]
    webshell_md5 = get_file_md5("./all/"+webshell_name)
    webshell_type = get_file_ext(webshell_name)
    # print_log(webshell_md5)
    check_sql = "select * from webshell where webshell_md5='"+webshell_md5+"'"
    # print_log(check_sql,3)
    exec_sql_res = cursor.execute(check_sql)
    if exec_sql_res==0:
        new_file_name = str(webshell_id)+"_"+webshell_md5+"."+webshell_type
        insert_sql = "insert into webshell(id,webshell_name,webshell_md5,webshell_type) value("+str(webshell_id)+",'"+new_file_name+"','"+webshell_md5+"','"+webshell_type+"')"
        # print_log(insert_sql)
        #插入数据库
        try:
            exec_sql_res = cursor.execute(insert_sql)
            print_log("插入成功:"+str(webshell_id)+"   "+webshell_name)
            db.commit()
            #文件转移
            shutil.move("./all/"+webshell_name,"./"+webshell_type+"/"+new_file_name)
        except pymysql.err.IntegrityError:
            print_log("插入错误:"+webshell_name,2)
            db.rollback()
    else:
        file_idx = file_idx-1
        select_res = cursor.fetchall()
        print(select_res[0][1]+"    ",end='')
        print_log(webshell_name+",已存在，不处理",2)
    
db.close()

'''
遍历all文件夹
获取文件md5，数据库查询是否存在
如果存在则抛出文件名
如果不存在则存到数据库里，并移动至相应的文件夹
'''
