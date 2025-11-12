LIB_PATH=./lib
TEST_PATH=./test
C_SRC_PATH=./C
LIB_FLAG=-shared -fPIC

build: clean sdflib sdftest

clean:
	rm -rf $(LIB_PATH)/*

sdflib:
	gcc $(C_SRC_PATH)/SDF.c $(LIB_FLAG) -o $(LIB_PATH)/libSDF.so

sdftest:
	make -C ./test
