#!/bin/bash
PACKAGE_DIR="./mmj"
BIN_DIR="./bin"
CLIENTSDF_DIR="./clientSDF"
CLIENTSDF_LIB_DIR="./clientSDF/lib"
CLIENTSDF_TEST_DIR="./clientSDF/test"
CREATED_FILE_DIR="./createdFile"
LIB_DIR="./lib"
USER_DIR="./user"
OBJTAR=$1

README="Readme"

if [ $# -lt 1 ]; then
    echo "usage : sh package.sh <obj_name.tar>"
    exit 1
fi

mkdir ${PACKAGE_DIR}
if [ $? -eq 0 ]; then
    echo "Make ${PACKAGE_DIR} dir successfully."
else
    echo "Make ${PACKAGE_DIR} dir failed"
    exit 1
fi

mkdir ${PACKAGE_DIR}/${CLIENTSDF_DIR}
if [ $? -eq 0 ]; then
    echo "Make ${PACKAGE_DIR}/${CLIENTSDF_DIR} dir successfully."
else
    echo "Make ${PACKAGE_DIR}/${CLIENTSDF_DIR} dir failed"
    exit 1
fi

cp -r ${BIN_DIR} ${PACKAGE_DIR} &> /dev/null 2>&1
cp -r ${CLIENTSDF_LIB_DIR} ${PACKAGE_DIR}/${CLIENTSDF_DIR} &> /dev/null 2>&1
cp -r ${CLIENTSDF_TEST_DIR} ${PACKAGE_DIR}/${CLIENTSDF_DIR} &> /dev/null 2>&1
cp -r ${CREATED_FILE_DIR} ${PACKAGE_DIR} &> /dev/null 2>&1
cp -r ${LIB_DIR} ${PACKAGE_DIR} &> /dev/null 2>&1
cp -r ${USER_DIR} ${PACKAGE_DIR} &> /dev/null 2>&1
cp -r ${README} ${PACKAGE_DIR} &> /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "cp dir successfully."
else
    echo "cp dir failed"
    exit 1
fi

sleep 1
tar -cvf ${OBJTAR} ${PACKAGE_DIR}
if [ $? -eq 0 ]; then
    echo "tar dir successfully."
else
    echo "tar dir failed"
    exit 1
fi

rm -rf  ${PACKAGE_DIR}
if [ $? -eq 0 ]; then
    echo "package ${OBJTAR} successfully."
else
    echo "package ${OBJTAR} failed"
    exit 1
fi