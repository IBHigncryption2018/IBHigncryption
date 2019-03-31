#!/bin/sh

num=10

if [ $# -gt 0 ] ; then
	num=$1
fi


PARA_FILE=../param/a.param
MODE2="模式2"
MODE1="模式1"

DATE=`date "+%Y%m%d%H%M%S"`
if  [ ! -d ../log ] ; then
	mkdir -p ../log
else
	mkdir -p ../log/backup.${DATE}
	mv ../log/*.txt ../log/backup.${DATE}
	mv ../log/*.log ../log/backup.${DATE}
fi


	echo "===== $MODE2 生成密钥 =====" >> ../log/keygen.log
	echo "===== $MODE1 生成密钥 =====" >> ../log/keygen1.log
	echo "===== $MODE2 加密 =====" >> ../log/enc.log
	echo "===== $MODE1 加密 =====" >> ../log/enc1.log
	echo "===== $MODE2 解密 =====" >> ../log/dec.log
	echo "===== $MODE1 解密 =====" >> ../log/dec1.log
	echo "===== $MODE2 加密解密 =====" >> ../log/enc_dec.log
	echo "===== $MODE1 加密解密 =====" >> ../log/enc_dec1.log
	echo "===== $MODE2 生成密钥加密解密 =====" >> ../log/gen_enc_dec.log
	echo "===== $MODE1 生成密钥加密解密 =====" >> ../log/gen_enc_dec1.log

echo "正在测试....`date '+%Y-%m-%d %H:%M:%S'`"
COUNT="1 10 100 1000 2000 4000 8000 10000 12000 16000 20000"
for c in $COUNT 
do
	echo "测试次数 $c `date '+%Y-%m-%d %H:%M:%S'`"
	# 测试生成密钥
	./key_gen $PARA_FILE $c >> ../log/keygen.log 
	./key_gen1 $PARA_FILE $c >> ../log/keygen1.log 
	./enc $PARA_FILE $c >> ../log/enc.log 
	./enc1 $PARA_FILE $c >> ../log/enc1.log 
	./dec $PARA_FILE $c >> ../log/dec.log 
	./dec1 $PARA_FILE $c >> ../log/dec1.log 
	./enc_dec $PARA_FILE $c >> ../log/enc_dec.log 
	./enc_dec1 $PARA_FILE $c >> ../log/enc_dec1.log 
	./gen_enc_dec $PARA_FILE $c >> ../log/gen_enc_dec.log 
	./gen_enc_dec1 $PARA_FILE $c >> ../log/gen_enc_dec1.log 
done

PWD=`pwd`

cd ../log
for FILE in `ls *.log `
do
	result=`echo $FILE | awk -F"." '{print $1}'`
	grep "=====" $FILE  >> $result.txt
	echo "   count total average" >> $result.txt
	grep success $FILE  | awk '{print $3, $12, $8}' | sed "s/\// /g" | awk '{printf("%-6d %-12s %-12s\n", $1, $3, $NF)}'  >> $result.txt
done
cd -

