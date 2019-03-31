libibh概述
======

libibh是一个基于身份的匿签密算法的C标准库实现，本算法有两个实现分别是libkem_ibh1.so 和 libkem_ibh3.so,分别对应在对称双线性映射群上的实现和在非对称双线性映射群上的实现。

依赖
------
libibh依赖gmp、pbc和openssl库


目录结构说明
-------

- ibh 动态库libibh的实现源码目录 
- lib 编译后动态库的目录
- test linux系统功能测试程序的目录
- param linux系统pbc库初始化安全参数文件
- benchmark 性能测试源码目录 
- example 功能测试源码目录 
- bin  Windows系统生成的可执行文件与库的目录 
- include 动态库api头文件
- makeall.sh  linux系统编译脚本，编译动态库、功能测试及性能测试程序
- makeclean.sh  linux系统清理脚本，清理makeall.sh生成的文件
- run_test.sh linux系统执行功能测试的脚本
- benchmark/run_benchmark.sh linux系统执行性能测试(耗时)的脚本
- benchmark/run_test_cpu.sh  linux系统执行性能测试(CPU时钟周期)的脚本
- benchmark/run_test_varlength.sh linux系统执行性能测试(封装解封不同密钥长度)的脚本

### 源代码功能说明
#### 目录ibh下文件列表
- cipher.c    密文处理  
- rand.c    随机数生成函数实现  
- plaint.c    明文处理函数实现  
- md5.c    Md5函数实现   
- kem_api.c    模式3接口函数实现  
- util.c    杂项  
- sha.c    sha函数实现  
- kem_api_single.c    模式1接口函数实现  
- str.c    字符串常见操作实现  
- secret_key.c    模式3密钥处理函数实现  
- secret_key1.c    模式1密钥处理函数实现  
- ibh.c    AES加解密及相关字符串处理 

#### 目录 benchmark 下主要文件列表
- enc.c 加密性能测试实现
- dec.c 解密性能测试实现
- gen_enc_dec.c 生成密钥加密解密测试实现 
- key_gen.c 生成密钥实现

#### 目录 example 下主要文件列表 
- varlength.c 变长密钥加密解密测试
- intercept.c  模拟敌方拦截测试实现
- length.c 变长密钥加密解密测试
- pairkey.c 正常功能测试实现
- modify_ct.c 异常修改密文测试
- modify_cert.c 异常修改证书测试


在Windows和Linux下的安装
---------------------------------------
我们已在Windows和Ubuntu下通过安装和测试
# Ubuntu下的安装与测试

## 安装openssl

```
    sudo apt-get install libssl 
    sudo apt-get install libssl-dev
```

## libgmp安装
安装libgmp的依赖flex与jison


```
    sudo apt-get install flex
    sudo apt-get install bison
```

去[gmp](https://gmplib.org/)官网下载最新的gmp包(libgmp-6.1.2.tar.bz2)

1、解压
```
tar xvf libgmp-6.1.2.tar.bz2
```
2、进入gmp-6.1.2目录
```
    cd libgmp-6.1.2
```
3、安装
```
   ./configure 
   make 
   make check
   sudo make install 
```

## libpbc安装
安装libpbc的依赖M4

```
    sudo apt-get install M4
```
去[pbc](https://crypto.stanford.edu/pbc/)官网下载最新的gmp包(libgmp-0.5.14.tar.bz2)

1、解压

```
tar xvf libgmp-6.1.2.tar.bz2
```

2、进入libgmp-0.5.14目录

```
    cd libgmp-0.5.14
```

3、安装

```
   ./configure 
   make 
   sudo make install 
```

4、设置环境变量

```
	export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
```

## 安装 libibh

1、解压

```
	tar xvf IBHigncryption.tar.bz2
```

2、进入IBHigncryption目录  

```
    cd IBHigncryption
```

3、设置环境变量  


```
	export LD_LIBRARY_PATH=$HOME/IBHigncryption/lib:$LD_LIBRARY_PATH 
	export IBH_MK=0E0104AFC246A48E145DAA2CFA0DC8CCCD079712 
```


4、安装测试 

```
	./makeall.sh

	./run_test.sh
```


# Windows下的安装与测试

第三方库依赖
-------
第三方依赖库已编译完成，放于bin目录下。分别是libgcc.a、libgmp.a、libmingw32.a、libmingwex.a、 libpbc.a、libgcc_eh.a、 libgcc_s.a,libcrypto-1_1.dll 和 libssl-1_1.dll。

环境依赖
---------
运行环境需要下载[VC++2010](https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x86.exe)和[VC++2015](https://download.microsoft.com/download/5/B/C/5BC5DBB3-652D-4DCE-B14A-475AB85EEF6E/vcredist_x86.exe)运行环境支持，如果已经安装了Windows Microsoft Visual Studio系列开发工具，可以不用下载。

编译安装
------
使用 Microsoft Visual Studio 2010打开 build/vs2010/lib_ibhigncryption/lib_ibhigncryption.sln、
build/vs2010/example/IBHigncryption.sln和
build/vs2010/benchmark/benchmark.sln 。分别编译。
编译的文件统一生成在bin目录下。


运行测试
------
1. 进行到bin目录
2. 双击 run_test.bat

测试实例
------
1. 进行到bin目录
2. 双击 run_case.bat
3. 在bin目录下生成type1测试实例case1.log和type3测试实例case3.log
