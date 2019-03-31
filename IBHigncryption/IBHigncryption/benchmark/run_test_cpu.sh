#!/bin/sh


num=10

if [ $# -gt 0 ] ; then
	num=$1
fi

LOG_PATH=../log
PARA_FILE=../param/a.param
MODE3="模式3"
MODE1="模式1"

DATE=`date "+%Y%m%d%H%M%S"`

echo "====== ${MODE3} ====" > $LOG_PATH/cpucycles.log
echo "====== ${MODE1} ====" > $LOG_PATH/cpucycles1.log

COUNT="10 20 100 200 400 800 1000"
for C in  $COUNT
do
	./cpucycles $PARA_FILE $C >> ../log/cpucycles.log
	./cpucycles1 $PARA_FILE $C >> ../log/cpucycles1.log
done



echo "正在测试...."
cd $LOG_PATH

rm -f cpucycles*.txt

for FILE in `ls cpucycles.log cpucycles1.log`
do
	result=`echo $FILE | awk -F"." '{print $1}'`


	RESULT_FILE=${result}_cpu_gen.txt
	grep "=====" $FILE  >> ${RESULT_FILE}
	echo "    type num total average " >> ${RESULT_FILE}
	grep kem_keygen $FILE | awk '{printf("%-12s %-8s %-12s %-12s\n", $1, $4, $5, $7)}' >> ${RESULT_FILE}

	RESULT_FILE=${result}_cpu_enc.txt
	grep "=====" $FILE  >> ${RESULT_FILE}
	echo "    type num total average " >> ${RESULT_FILE}
	grep kem_key_enc $FILE | awk '{printf("%-12s %-8s %-12s %-12s\n", $1, $4, $5, $7)}' >> ${RESULT_FILE}

	RESULT_FILE=${result}_cpu_dec.txt
	grep "=====" $FILE  >> ${RESULT_FILE}
	echo "    type num total average " >> ${RESULT_FILE}
	grep kem_key_dec $FILE | awk '{printf("%-12s %-8s %-12s %-12s\n", $1, $4, $5, $7)}' >> ${RESULT_FILE}
done
	cat cpucycles*.txt
cd -
