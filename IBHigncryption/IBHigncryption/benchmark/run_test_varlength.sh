#!/bin/sh


num=10

if [ $# -gt 0 ] ; then
	num=$1
fi

LOG_PATH=../log
PARA_FILE=../param/a.param
MODE2="模式2"
MODE1="模式1"

DATE=`date "+%Y%m%d%H%M%S"`

echo "MODE3" > $LOG_PATH/varlength.log
echo "MODE1" > $LOG_PATH/varlength1.log

step=32
length=1048576
echo "===== $MODE2 加密解密不同长度 =====" >> ../log/varlength.log

while [ $step -le $length  ]
do
	echo "加密解密长度 $step  `date +'%Y-%m-%d %H:%M:%S'`"
	./varlength     $PARA_FILE $num  $step  >> $LOG_PATH/varlength.log
	./varlength1     $PARA_FILE $num  $step  >> $LOG_PATH/varlength1.log
step=`expr $step + $step`
done

echo "正在测试...."
cd ../log
for FILE in `ls varlength.log varlength1.log`
do
	result=`echo $FILE | awk -F"." '{print $1}'`
	grep "=====" $FILE  >> $result.txt
	echo "    count length total average " >> $result.txt
	grep success $FILE | awk '{print $3, $12, $8, $NF}' | sed "s/\// /g"  | awk '{printf("%-6d %-8d %-12s %-12s\n", $1, $NF, $3, $4)}' >> $result.txt
done
cat *.txt
cd -
