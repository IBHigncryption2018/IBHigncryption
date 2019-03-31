#!/bin/sh


PWD=`pwd`
LIB_PATH=
n=`whereis libgmp | awk '{print NF}'`
if [ $n -eq 1 ] ; then
	GMP_LIB_PATH=`find $HOME -name libgmp*.so `
	if [ -z "$GMP_LIB_PATHS" ] ; then 
		echo "libgmp can't found in system, please install libgmp"
	else
		for D in `echo $GMP_LIB_PATHS`
		do
			if [ -f $D ] ; then
				GMP_LIB_PATH=`dirname $D`
			fi
		done
	fi
fi
if [ -n "$GMP_LIB_PATH" ] ; then
	LIB_PATH="$LIB_PATH:$GMP_LIB_PATH"
fi
n=`whereis libpbc | awk '{print NF}'`
if [ $n -eq 1 ] ; then
	PBC_LIB_PATHS=`find $HOME -name libpbc*.so `
	if [ -z "$PBC_LIB_PATHS" ] ; then 
		echo "libgmp can't found in system, please install libgmp"
	else
		for D in `echo $PBC_LIB_PATHS`
		do
			if [ -f $D ] ; then
				PBC_LIB_PATH=`dirname $D`
			fi
		done
	fi
fi
if [ -n "$PBC_LIB_PATH" ] ; then
	LIB_PATH="$LIB_PATH:$PBC_LIB_PATH"
fi

if [ -n "$LIB_PATH" ] ; then
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIB_PATH
fi
