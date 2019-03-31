#!/bin/sh

#检查依赖



if [ ! -d lib ] ; then
	mkdir -p lib
fi

SUBDIR="ibh example benchmark"
for D in $SUBDIR
do
	cd $D
	 make clean
	cd ..
done

