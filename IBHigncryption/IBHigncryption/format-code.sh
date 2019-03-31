#!/bin/sh

#================================================================
#   Copyright (C) 2019 Chinaums Ltd. 	All rights reserved.
#   
#   文件名称:format-code.sh
#   创 建 者:xiang_kgd@163.com
#   创建日期:2019年01月15日
#   描    述:
#
#================================================================


find . -name *.c | while read line
do
clang-format -i -style=LLVM -sort-includes $line
done

find . -name *.h | while read line
do
clang-format -i -style=LLVM -sort-includes $line
done
