#!/bin/bash

tags="mysql"

first_argument=$1

script_path=$(realpath "$0")
script_dir=$(dirname "$script_path")
export LD_LIBRARY_PATH=${script_dir}/../lib

usage(){
    echo "sh gotest.sh No."
    echo "1.销毁&创建数据库测试"
    echo "2.添加对称&SM2密钥测试"
    echo "3.读取配置文件测试"
    echo "4.算法正确性校验测试"
    echo "5.密钥完整性校验测试"
    echo "6.上电检测测试"
    echo "7.周期检测测试"
    echo "8.注册管理员"
}

if [ "$first_argument" == "1" ]; then
    cd kmtest
    go test -run TestDestorySql -tags=${tags}
    go test -run TestCreateSql -tags=${tags}
    cd -
elif [ "$first_argument" == "2" ]; then
    cd msAPItest
    go test -run TestAddKey -tags=${tags}
    cd -
elif [ "$first_argument" == "3" ]; then
    cd basetest
    go test -run TestReadConf -tags=${tags}
    cd -
elif [ "$first_argument" == "4" ]; then
    cd inittest
    go test -run TestAlgCorrectnessCheck -tags=${tags}
    cd -
elif [ "$first_argument" == "5" ]; then
    rm -rf CreatedFile
    cp -r ../CreatedFile ./
    cp ../Bin/kek-1.key ./inittest
    cd inittest
    go test -run TestKeyLoad -tags=${tags}
    rm -rf kek-1.key
    cd -
    rm -rf CreatedFile
elif [ "$first_argument" == "6" ]; then
    cd inittest
    go test -run TestPowerOnDetection -tags=${tags}
    cd -
elif [ "$first_argument" == "7" ]; then
    cd inittest
    go test -run TestCycleDetection -tags=${tags}
    cd -
elif [ "$first_argument" == "8" ]; then
    cd msAPItest
    go test -run TestAddUser -tags=${tags}
    cd -
else 
    usage
fi
