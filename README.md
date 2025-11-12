## 运行项目 ##
tar -xvf mmj.tar 
cd mmj
## 1.管理服务 ##
cd ./bin
#vi config.conf 配置管理服务的启动IP和PORT
./manageserver &
cd -

## 2.管理工具 ##
cd ./bin
./managetool
cd - 
##进入管理工具后，需要先根据引导初始化设备

## 3.密码服务 ##
cd ./bin
./cryptoserver &
cd - 

## 4.客户端SDF ##
## 测试demo SDF_test.c 软算法无SM1 无RSA
#
#
# 未开发完 
# 仅供测试
# 可当软密码机用

