# -*- coding:utf-8 -*-

# Read libs.json
import json
import pymongo


file_libs = open("libs.json", "r")
str_libs = file_libs.readline()
libs = json.loads(str_libs)
file_libs.close()
cnt = 0

s_pathes = {}
for lib in libs:
    # print lib
    s_pathes[lib['pack_name']] = {}
    # s_pathes.append(lib['pack_name'])



pyClient = pymongo.MongoClient("localhost", 27017)
lib_detect = pyClient["lib-detect"]
brief_packages = lib_detect['brief_packages']
packages = brief_packages.find().limit(10000000)
for pack in packages:
    if pack['s_path'] in s_pathes:
        # print pack
        if pack['b_hash'] in s_pathes[pack['s_path']]:
            s_pathes[pack['s_path']][pack['b_hash']].append(pack['apk'])
        else:
            s_pathes[pack['s_path']][pack['b_hash']] = []
            s_pathes[pack['s_path']][pack['b_hash']].append(pack['apk'])

output = open("lve_limit10m.txt",'w')

for lib in libs:
    output.write(lib['pack_name'] + '\n')
    for hashCode in s_pathes[lib['pack_name']]:
        output.write("  " + str(hashCode) + '\n')
        for apk_path in s_pathes[lib['pack_name']][hashCode]:
            output.write("    " + apk_path.split('/')[-1] + "\n")
output.close()

pyClient.close()