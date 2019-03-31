#!/bin/sh

#================================================================
#   Copyright (C) 2019 Chinaums Ltd. 	All rights reserved.
#   
#   文件名称:run_test.sh
#   创 建 者:xiang_kgd@163.com
#   创建日期:2019年01月15日
#   描    述:
#
#================================================================

TEST_DIR="test"
for D in $TEST_DIR
do
	cd $D
	if [ -f run_test.sh ] ; then
		./run_test.sh
	fi
	cd ..
done

