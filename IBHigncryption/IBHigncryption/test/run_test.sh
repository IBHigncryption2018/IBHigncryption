
#!/bin/sh


PARA_FILE=../param/a.param

./intercept   		$PARA_FILE 
./pairkey   		$PARA_FILE 
./length            $PARA_FILE   32
./length            $PARA_FILE   64
./length            $PARA_FILE   128


./intercept1   		$PARA_FILE 
./pairkey1   		$PARA_FILE 
./length1            $PARA_FILE   32
./length1            $PARA_FILE   64
./length1            $PARA_FILE   128
