#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "SDF.h"
#include <pthread.h>
#include <ctype.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

#define CSTLIST_MAX 1000
#define READBUFFERMAX_LEN 1024 * 1024 * 16
#define BIGENDIAN 1

unsigned char IP1[24];
unsigned int Port1;

typedef struct
{
    void *sesh;
    int conn;
} cst;

cst UPCa[CSTLIST_MAX];

void upcaClear(cst *upca)
{
    upca->sesh = NULL;
    close(upca->conn);
}

unsigned long htonll(unsigned long value)
{
#if (BIGENDIAN == 1)
    return ((unsigned long)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);

#else
    return value;
#endif
}

unsigned long ntohll(unsigned long value)
{
#if (BIGENDIAN == 1)
    return ((unsigned long)ntohl(value & 0xFFFFFFFF) << 32) | ntohl(value >> 32);
#else
    return value;
#endif
}

#define MAX_LINE_LENGTH 256

char *trim(char *str)
{
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)
        return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    *(end + 1) = '\0';

    return str;
}

char *get_config_value(const char *filename, const char *key)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("Could not open file");
        return NULL;
    }

    char line[MAX_LINE_LENGTH];
    char *value = NULL;

    while (fgets(line, sizeof(line), file))
    {
        char *trimmed_line = trim(line);

        char *delimiter = strchr(trimmed_line, '=');
        if (delimiter)
        {
            *delimiter = '\0';
            char *found_key = trim(trimmed_line);
            char *found_value = trim(delimiter + 1);

            if (strcmp(found_key, key) == 0)
            {
                value = strdup(found_value); // Duplicate the value string
                break;
            }
        }
    }

    fclose(file);
    return value;
}

// 1. 打开设备
int SDF_OpenDevice(void **devh)
{

    return 0;
}

// 2. 关闭设备
int SDF_CloseDevice(void *devh)
{
    return 0;
}

// 3. 创建会话
int SDF_OpenSession(void *devh, void **sesh)
{
    unsigned int len = 8;
    unsigned int cmd = 0x5003;
    struct sockaddr_in server_addr;
    int sockfd;
    int recv_ret;
    unsigned long recv_sesh;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return SDR_OPENSESSION;

    server_addr.sin_family = AF_INET;
    unsigned int sport;
    unsigned char *sportstr;
    sportstr = get_config_value("./config.conf", "CRYPTOSERVER_PORT");
    server_addr.sin_port = htons(atoi(sportstr));
    unsigned char *sipstr;
    sipstr = get_config_value("./config.conf", "CRYPTOSERVER_IP");

    inet_pton(AF_INET, sipstr, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        close(sockfd);
        return SDR_OPENSESSION;
    }

    char sendBuffer[8];
    char readBuffer[16];

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);

    if (send(sockfd, sendBuffer, len, 0) != len)
    {
        close(sockfd);
        return SDR_OPENSESSION;
    }

    if (recv(sockfd, readBuffer, 8, 0) != 8)
    {
        close(sockfd);
        return SDR_OPENSESSION;
    }

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(sockfd, readBuffer, 8, 0) != 8)
        {
            close(sockfd);
            return SDR_OPENSESSION;
        }
        recv_sesh = ntohll(*((unsigned long *)(readBuffer)));

        pthread_mutex_lock(&lock);
        int i;
        for (i = 0; i < CSTLIST_MAX; i++)
        {
            if (UPCa[i].sesh == NULL)
            {
                UPCa[i].sesh = (void *)recv_sesh;
                UPCa[i].conn = sockfd;
                *sesh = (void *)&UPCa[i];
                pthread_mutex_unlock(&lock);
                return 0;
            }
        }
        pthread_mutex_unlock(&lock);
    }
    close(sockfd);
    return CONNECTION_LIMIT;
}

// 4. 关闭会话
int SDF_CloseSession(void *sesh)
{
    unsigned int len = 16;
    unsigned int cmd = 0x5004;
    cst *upca = (cst *)sesh;
    uint8_t sendBuffer[16];
    uint8_t readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret == 0)
        upcaClear(upca);
    return recv_ret;
}

// 5. 获取设备信息
int SDF_GetDeviceInfo(void *sesh, DEVICEINFO *devinfo)
{
    unsigned int len = 16;
    unsigned int cmd = 0x5005;
    cst *upca = (cst *)sesh;
    char sendBuffer[16];
    char readBuffer[8];
    int recv_ret;
    int sec_redlen;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        sec_redlen = ntohl(*((unsigned int *)(readBuffer))) - 8;
        if (recv(upca->conn, (void *)devinfo, sec_redlen, 0) != sec_redlen)
            return SDR_UNKNOWERR;

        devinfo->DeviceVersion = ntohl(devinfo->DeviceVersion);
        devinfo->StandardVersion = ntohl(devinfo->StandardVersion);
        devinfo->AsymAlgAbility[0] = ntohl(devinfo->AsymAlgAbility[0]);
        devinfo->AsymAlgAbility[1] = ntohl(devinfo->AsymAlgAbility[1]);
        devinfo->SymAlgAbility = ntohl(devinfo->SymAlgAbility);
        devinfo->HashAlgAbility = ntohl(devinfo->HashAlgAbility);
        devinfo->BufferSize = ntohl(devinfo->BufferSize);
    }

    return 0;
}

// 6. 产生随机数
int SDF_GenerateRandom(void *sesh, unsigned int uiLength, unsigned char *pucRandom)
{
    unsigned int len = 20;
    unsigned int cmd = 0x5006;
    cst *upca = (cst *)sesh;
    char sendBuffer[20];
    char readBuffer[8];

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    int recv_ret;
    int recv_len;
    recv_len = ntohl(*((unsigned int *)(readBuffer)));
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));

    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucRandom, uiLength, 0) != uiLength)
            return SDR_UNKNOWERR;
    }

    return 0;
}

// 7. 获取私钥使用权限
int SDF_GetPrivateKeyAccessRight(void *sesh, unsigned int uiKeyIndex,
                                 unsigned char *pucPassword, unsigned int uiPwdLength)
{
    unsigned int len = 8 + 8 + 4 + uiPwdLength;
    unsigned int cmd = 0x5007;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2 - 1);
    memcpy(sendBuffer + 20, pucPassword, uiPwdLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 8. 释放私钥使用权限
int SDF_ReleasePrivateKeyAccessRight(void *sesh, unsigned int uiKeyIndex)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x5008;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2 - 1);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 9. 导出ＲＳＡ签名公钥
int SDF_ExportSignPublicKey_RSA(void *sesh, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x6001;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2 - 1);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;

    if (recv(upca->conn, pucPublicKey, sizeof(RSArefPublicKey), 0) != sizeof(RSArefPublicKey))
        return SDR_UNKNOWERR;
    pucPublicKey->bits = htonl(pucPublicKey->bits);
    return 0;
}

// 10. 导出ＲＳＡ加密公钥
int SDF_ExportEncPublicKey_RSA(void *sesh, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x6002;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucPublicKey, sizeof(RSArefPublicKey), 0) != sizeof(RSArefPublicKey))
            return SDR_UNKNOWERR;
        pucPublicKey->bits = htonl(pucPublicKey->bits);
    }

    return 0;
}

// 11. 产生ＲＳＡ非对称密钥对并输出
int SDF_GenerateKeyPair_RSA(void *sesh, unsigned int uiKeyBits,
                            RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x6003;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyBits);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucPublicKey, sizeof(RSArefPublicKey), 0) != sizeof(RSArefPublicKey))
            return SDR_UNKNOWERR;
        pucPublicKey->bits = htonl(pucPublicKey->bits);
        if (recv(upca->conn, pucPrivateKey, sizeof(RSArefPrivateKey), 0) != sizeof(RSArefPrivateKey))
            return SDR_UNKNOWERR;
        pucPrivateKey->bits = htonl(pucPrivateKey->bits);
    }

    return 0;
}

// 12. 生成会话密钥并用内部ＲＳＡ公钥加密输出
int SDF_GenerateKeyWithIPK_RSA(void *sesh, unsigned int uiIPKIndex, unsigned int uiKeyBits,
                               unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + 4;
    unsigned int cmd = 0x6004;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiIPKIndex * 2);
    *((unsigned int *)(sendBuffer + 20)) = htonl(uiKeyBits);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucKey, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;

        *puiKeyLength = recv_len - 8;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(pucKey + recv_len - 8)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 13. 生成会话密钥并用外部ＲＳＡ公钥加密输出
int SDF_GenerateKeyWithEPK_RSA(void *sesh, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
                               unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + sizeof(RSArefPublicKey);
    unsigned int cmd = 0x6005;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyBits);
    *((unsigned int *)(sendBuffer + 20)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 24, pucPublicKey->m, sizeof(pucPublicKey->m));
    memcpy(sendBuffer + 24 + sizeof(pucPublicKey->m), pucPublicKey->e, sizeof(pucPublicKey->e));

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucKey, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiKeyLength = recv_len - 8;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(pucKey + recv_len - 8)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 14. 导入会话密钥并用内部ＲＳＡ私钥解密
int SDF_ImportKeyWithISK_RSA(void *sesh, unsigned int uiISKIndex,
                             unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + uiKeyLength;
    unsigned int cmd = 0x6006;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiISKIndex * 2);
    memcpy(sendBuffer + 20, pucKey, uiKeyLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
            return SDR_UNKNOWERR;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 15. 基于ＲＳＡ算法的数字信封转换
int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *sesh, unsigned int uiKeyIndex,
                                       RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput,
                                       unsigned int uiDELength, unsigned char *pucDEOutput,
                                       unsigned int *puiDELength)
{
    unsigned int len = 8 + 8 + 4 + sizeof(RSArefPublicKey) + uiDELength;
    unsigned int cmd = 0x6007;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2);
    *((unsigned int *)(sendBuffer + 20)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 24, pucPublicKey->m, sizeof(pucPublicKey->m));
    memcpy(sendBuffer + 24 + sizeof(pucPublicKey->m), pucPublicKey->e, sizeof(pucPublicKey->e));
    memcpy(sendBuffer + 24 + sizeof(pucPublicKey->m) * 2, pucDEInput, uiDELength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucDEOutput, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiDELength = recv_len;
    }
    return 0;
}

// 16. 导出ＥＣＣ签名公钥
int SDF_ExportSignPublicKey_ECC(void *sesh, unsigned int uiKeyIndex,
                                ECCrefPublicKey *pucPublicKey)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x6008;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2 - 1);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;

    if (recv(upca->conn, pucPublicKey, sizeof(ECCrefPublicKey), 0) != sizeof(ECCrefPublicKey))
        return SDR_UNKNOWERR;
    pucPublicKey->bits = htonl(pucPublicKey->bits);
    return 0;
}

// 17. 导出ＥＣＣ加密公钥
int SDF_ExportEncPublicKey_ECC(void *sesh, unsigned int uiKeyIndex,
                               ECCrefPublicKey *pucPublicKey)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x6009;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;

    if (recv(upca->conn, pucPublicKey, sizeof(ECCrefPublicKey), 0) != sizeof(ECCrefPublicKey))
        return SDR_UNKNOWERR;
    pucPublicKey->bits = htonl(pucPublicKey->bits);
    return 0;
}

// 18. 产生ＥＣＣ非对称密钥对并输出
int SDF_GenerateKeyPair_ECC(void *sesh, unsigned int uiAlgID,
                            unsigned int uiKeyBits,
                            ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
    unsigned int len = 8 + 8 + 4;
    unsigned int cmd = 0x600A;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyBits);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucPublicKey, sizeof(ECCrefPublicKey), 0) != sizeof(ECCrefPublicKey))
            return SDR_UNKNOWERR;
        pucPublicKey->bits = htonl(pucPublicKey->bits);
        if (recv(upca->conn, pucPrivateKey, sizeof(ECCrefPrivateKey), 0) != sizeof(ECCrefPrivateKey))
            return SDR_UNKNOWERR;
        pucPrivateKey->bits = htonl(pucPrivateKey->bits);
    }

    return 0;
}

// 19. 生成会话密钥并用内部ＥＣＣ公钥加密输出
int SDF_GenerateKeyWithIPK_ECC(void *sesh, unsigned int uiIPKIndex,
                               unsigned int uiKeyBits,
                               ECCCipher *pucKey, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + 4;
    unsigned int cmd = 0x600B;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiIPKIndex * 2);
    *((unsigned int *)(sendBuffer + 20)) = htonl(uiKeyBits);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucKey, sizeof(ECCCipher), 0) != sizeof(ECCCipher))
            return SDR_UNKNOWERR;
        pucKey->L = htonl(pucKey->L);
        if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
            return SDR_UNKNOWERR;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 20. 生成会话密钥并用外部ＥＣＣ公钥加密输出
int SDF_GenerateKeyWithEPK_ECC(void *sesh, unsigned int uiKeyBits,
                               unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                               ECCCipher *pucKey, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + sizeof(ECCrefPublicKey);
    unsigned int cmd = 0x600C;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyBits);
    *((unsigned int *)(sendBuffer + 20)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 24, pucPublicKey->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 24 + ECCref_MAX_LEN, pucPublicKey->y, ECCref_MAX_LEN);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucKey, sizeof(ECCCipher), 0) != sizeof(ECCCipher))
            return SDR_UNKNOWERR;
        pucKey->L = htonl(pucKey->L);
        if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
            return SDR_UNKNOWERR;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 21. 导入会话密钥并用内部ＥＣＣ私钥解密
int SDF_ImportKeyWithISK_ECC(void *sesh, unsigned int uiISKIndex,
                             ECCCipher *pucKey, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + sizeof(ECCCipher) + 4 + 4;
    unsigned int cmd = 0x600D;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiISKIndex * 2);
    memcpy(sendBuffer + 20, pucKey->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucKey->y, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 2, pucKey->M, ECCref_MAX_LEN / 2);
    *((unsigned int *)(sendBuffer + 20 + ECCref_MAX_LEN * 2 + ECCref_MAX_LEN / 2)) = htonl(pucKey->L);
    memcpy(sendBuffer + 28 + ECCref_MAX_LEN * 2 + ECCref_MAX_LEN / 2, pucKey->C, ECCref_MAX_CIPHER_LEN);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
        return SDR_UNKNOWERR;
    unsigned long recv_keyh;
    recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
    *phKeyHandle = (void *)recv_keyh;
    return 0;
}

// 22. 生成密钥协商参数并输出
int SDF_GenerateAgreementDataWithECC(void *sesh,
                                     unsigned int uiISKIndex, unsigned int uiKeyBits,
                                     unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                     ECCrefPublicKey *pucSponsorPublicKey,
                                     ECCrefPublicKey *pucSponsorTmpPublicKey,
                                     void **phAgreementHandle)
{
    unsigned int len = 8 + 8 + 4 + 4 + uiSponsorIDLength;
    unsigned int cmd = 0x600E;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiISKIndex * 2);
    *((unsigned int *)(sendBuffer + 20)) = htonl(uiKeyBits);
    memcpy(sendBuffer + 24, pucSponsorID, uiSponsorIDLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;

    if (recv(upca->conn, pucSponsorPublicKey, sizeof(ECCrefPublicKey), 0) != sizeof(ECCrefPublicKey))
        return SDR_UNKNOWERR;
    pucSponsorPublicKey->bits = htonl(pucSponsorPublicKey->bits);

    if (recv(upca->conn, pucSponsorTmpPublicKey, sizeof(ECCrefPublicKey), 0) != sizeof(ECCrefPublicKey))
        return SDR_UNKNOWERR;
    pucSponsorTmpPublicKey->bits = htonl(pucSponsorTmpPublicKey->bits);

    if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
        return SDR_UNKNOWERR;
    unsigned long recv_keyh;
    recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
    *phAgreementHandle = (void *)recv_keyh;
}

// 25. 基于 ＥＣＣ算法的数字信封转换
int SDF_ExchangeDigitEnvelopeBaseOnECC(void *sesh,
                                       unsigned int uiKeyIndex, unsigned int uiAlgID,
                                       ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
                                       ECCCipher *pucEncDataOut)
{
    unsigned int len = 8 + 8 + 4 + sizeof(ECCrefPublicKey) + sizeof(ECCCipher) + 4;
    unsigned int cmd = 0x6012;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2);
    *((unsigned int *)(sendBuffer + 20)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 24, pucPublicKey->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 24 + ECCref_MAX_LEN, pucPublicKey->y, ECCref_MAX_LEN);
    memcpy(sendBuffer + 24 + ECCref_MAX_LEN * 2, pucEncDataIn->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 24 + ECCref_MAX_LEN * 3, pucEncDataIn->y, ECCref_MAX_LEN);
    memcpy(sendBuffer + 24 + ECCref_MAX_LEN * 4, pucEncDataIn->M, ECCref_MAX_LEN / 2);
    *((unsigned int *)(sendBuffer + 24 + ECCref_MAX_LEN * 4 + ECCref_MAX_LEN / 2)) = htonl(pucEncDataIn->L);
    memcpy(sendBuffer + 32 + ECCref_MAX_LEN * 4 + ECCref_MAX_LEN / 2, pucEncDataIn->C, ECCref_MAX_CIPHER_LEN);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucEncDataOut, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        pucEncDataOut->L = htonl(pucEncDataOut->L);
    }
    return 0;
}

// 26. 生成会话密钥并用密钥加密密钥加密输出
int SDF_GenerateKeyWithKEK(void *sesh,
                           unsigned int uiKeyBits, unsigned int uiAlgID,
                           unsigned int uiKEKIndex, unsigned char *pucKey,
                           unsigned int *puiKeyLength, void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + 4 + 4;
    unsigned int cmd = 0x6013;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyBits);
    *((unsigned int *)(sendBuffer + 20)) = htonl(uiAlgID);
    *((unsigned int *)(sendBuffer + 24)) = htonl(uiKEKIndex);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucKey, recv_len - 8, 0) != recv_len - 8)
            return SDR_UNKNOWERR;
        *puiKeyLength = recv_len - 8;
        if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
            return SDR_UNKNOWERR;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 27. 导入会话密钥并用密钥加密密钥解密
int SDF_ImportKeyWithKEK(void *sesh,
                         unsigned int uiAlgID, unsigned int uiKEKIndex,
                         unsigned char *pucKey, unsigned int uiKeyLength,
                         void **phKeyHandle)
{
    unsigned int len = 8 + 8 + 4 + 4 + uiKeyLength;
    unsigned int cmd = 0x6014;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiAlgID);
    *((unsigned int *)(sendBuffer + 20)) = htonl(uiKEKIndex);
    memcpy(sendBuffer + 24, pucKey, uiKeyLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;

    if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
        return SDR_UNKNOWERR;
    unsigned long recv_keyh;
    recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
    *phKeyHandle = (void *)recv_keyh;

    return 0;
}

// 28. 导入明文会话密钥
int SDF_ImportKey(void *sesh,
                  unsigned char *pucKey, unsigned int uiKeyLength,
                  void **phKeyHandle)
{
    unsigned int len = 8 + 8 + uiKeyLength;
    unsigned int cmd = 0x6015;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    memcpy(sendBuffer + 16, pucKey, uiKeyLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, readBuffer, sizeof(readBuffer), 0) != sizeof(readBuffer))
            return SDR_UNKNOWERR;
        unsigned long recv_keyh;
        recv_keyh = ntohll(*((unsigned long *)(readBuffer)));
        *phKeyHandle = (void *)recv_keyh;
    }
    return 0;
}

// 29. 销毁会话密钥
int SDF_DestroyKey(void *sesh, void *hKeyHandle)
{
    unsigned int len = 8 + 8 + 8;
    unsigned int cmd = 0x6016;
    cst *upca = (cst *)sesh;
    char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned long *)(sendBuffer + 16)) = htonll((uint64_t)(uintptr_t)hKeyHandle);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 非对称算法运算类函数
// 30. 外部公钥ＲＳＡ运算
int SDF_ExternalPublicKeyOperation_RSA(void *sesh,
                                       RSArefPublicKey *pucPublicKey,
                                       unsigned char *pucDataInput, unsigned int uiInputLength,
                                       unsigned char *pucDataOutput, unsigned int *puiOutputLength)
{
    unsigned int len = 8 + 8 + sizeof(RSArefPublicKey) + uiInputLength;
    unsigned int cmd = 0x7001;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 20, pucPublicKey->m, RSAref_MAX_LEN);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN, pucPublicKey->e, RSAref_MAX_LEN);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 2, pucDataInput, uiInputLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucDataOutput, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiOutputLength = recv_len;
    }
    return 0;
}

// 31. 外部私钥ＲＳＡ运算
int SDF_ExternalPrivateKeyOperation_RSA(void *sesh,
                                        RSArefPrivateKey *pucPrivateKey,
                                        unsigned char *pucDataInput, unsigned int uiInputLength,
                                        unsigned char *pucDataOutput, unsigned int *puiOutputLength)
{
    unsigned int len = 8 + 8 + sizeof(RSArefPrivateKey) + uiInputLength;
    unsigned int cmd = 0x7002;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;
    memset(sendBuffer, 0x00, 64);
    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(pucPrivateKey->bits);
    memcpy(sendBuffer + 20, pucPrivateKey->m, RSAref_MAX_LEN);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN, pucPrivateKey->e, RSAref_MAX_LEN);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 2, pucPrivateKey->d, RSAref_MAX_LEN);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 3, pucPrivateKey->prime[0], RSAref_MAX_LEN / 2);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 3 + RSAref_MAX_LEN / 2, pucPrivateKey->prime[1], RSAref_MAX_LEN / 2);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 4, pucPrivateKey->pexp[0], RSAref_MAX_LEN / 2);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 4 + RSAref_MAX_LEN / 2, pucPrivateKey->pexp[1], RSAref_MAX_LEN / 2);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 5, pucPrivateKey->coef, RSAref_MAX_LEN / 2);
    memcpy(sendBuffer + 20 + RSAref_MAX_LEN * 5 + RSAref_MAX_LEN / 2, pucDataInput, uiInputLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucDataOutput, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiOutputLength = recv_len;
    }
    return 0;
}

// 32. 内部公钥ＲＳＡ运算
int SDF_InternalPublicKeyOperation_RSA(void *sesh,
                                       unsigned int uiKeyIndex,
                                       unsigned char *pucDataInput, unsigned int uiInputLength,
                                       unsigned char *pucDataOutput, unsigned int *puiOutputLength)
{
    unsigned int len = 8 + 8 + 4 + uiInputLength;
    unsigned int cmd = 0x7003;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2);
    memcpy(sendBuffer + 20, pucDataInput, uiInputLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucDataOutput, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiOutputLength = recv_len;
    }
    return 0;
}

// 33. 内部私ＲＳＡ运算
int SDF_InternalPrivateKeyOperation_RSA(void *sesh,
                                        unsigned int uiKeyIndex,
                                        unsigned char *pucDataInput, unsigned int uiInputLength,
                                        unsigned char *pucDataOutput, unsigned int *puiOutputLength)
{
    unsigned int len = 8 + 8 + 4 + uiInputLength;
    unsigned int cmd = 0x7004;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiKeyIndex * 2);
    memcpy(sendBuffer + 20, pucDataInput, uiInputLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucDataOutput, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiOutputLength = recv_len;
    }
    return 0;
}

// 34. 外部密钥ＥＣＣ签名
int SDF_ExternalSign_ECC(void *sesh,
                         unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                         unsigned char *pucData, unsigned int uiDataLength,
                         ECCSignature *pucSignature)
{
    unsigned int len = 8 + 8 + sizeof(ECCrefPrivateKey) + uiDataLength;
    unsigned int cmd = 0x7005;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(pucPrivateKey->bits);
    memcpy(sendBuffer + 20, pucPrivateKey->K, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    // recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucSignature, sizeof(ECCSignature), 0) != sizeof(ECCSignature))
            return SDR_UNKNOWERR;
    }
    return 0;
}

// 35. 外部密钥ＥＣＣ验证
int SDF_ExternalVerify_ECC(void *sesh,
                           unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucDataInput, unsigned int uiInputLength,
                           ECCSignature *pucSignature)
{
    unsigned int len = 8 + 8 + sizeof(ECCrefPublicKey) + uiInputLength + sizeof(ECCSignature);
    unsigned int cmd = 0x7006;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 20, pucPublicKey->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucPublicKey->y, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 2, pucSignature->r, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 3, pucSignature->s, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 4, pucDataInput, uiInputLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    // recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 36. 内部密钥ＥＣＣ签名
int SDF_InternalSign_ECC(void *sesh,
                         unsigned int uiISKIndex, unsigned char *pucData,
                         unsigned int uiDataLength, ECCSignature *pucSignature)
{
    unsigned int len = 8 + 8 + 4 + uiDataLength;
    unsigned int cmd = 0x7007;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiISKIndex * 2 - 1);
    memcpy(sendBuffer + 20, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    // recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucSignature, sizeof(ECCSignature), 0) != sizeof(ECCSignature))
            return SDR_UNKNOWERR;
    }
    return 0;
}

// 37. 内部密钥ＥＣＣ验证
int SDF_InternalVerify_ECC(void *sesh,
                           unsigned int uiISKIndex, unsigned char *pucData,
                           unsigned int uiDataLength, ECCSignature *pucSignature)
{

    unsigned int len = 8 + 8 + 4 + uiDataLength + sizeof(ECCSignature);
    unsigned int cmd = 0x7008;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiISKIndex * 2 - 1);
    memcpy(sendBuffer + 20, pucSignature->r, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucSignature->s, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 2, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    // recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 38. 外部密钥ＥＣＣ加密
int SDF_ExternalEncrypt_ECC(void *sesh,
                            unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                            unsigned char *pucData, unsigned int uiDataLength,
                            ECCCipher *pucEncData)
{

    unsigned int len = 8 + 8 + sizeof(ECCrefPublicKey) + uiDataLength;
    unsigned int cmd = 0x7009;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(pucPublicKey->bits);
    memcpy(sendBuffer + 20, pucPublicKey->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucPublicKey->y, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 2, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    // recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucEncData, sizeof(ECCCipher), 0) != sizeof(ECCCipher))
            return SDR_UNKNOWERR;
        pucEncData->L = htonl(pucEncData->L);
    }
    return 0;
}

// 39. 外部密钥ＥＣＣ解密
int SDF_ExternalDecrypt_ECC(void *sesh,
                            unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
                            ECCCipher *pucEncData,
                            unsigned char *pucData, unsigned int *puiDataLength)
{
    unsigned int len = 8 + 8 + sizeof(ECCrefPrivateKey) + sizeof(ECCCipher) + 4;
    unsigned int cmd = 0x700A;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(pucPrivateKey->bits);
    memcpy(sendBuffer + 20, pucPrivateKey->K, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucEncData->x, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 2, pucEncData->y, ECCref_MAX_LEN);
    memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 3, pucEncData->M, ECCref_MAX_LEN / 2);
    *((unsigned int *)(sendBuffer + 20 + ECCref_MAX_LEN * 3 + ECCref_MAX_LEN / 2)) = htonl(pucEncData->L);
    memcpy(sendBuffer + 24 + ECCref_MAX_LEN * 3 + ECCref_MAX_LEN / 2, pucEncData->C, ECCref_MAX_CIPHER_LEN);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucData, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiDataLength = recv_len;
    }
    return 0;
}

// 对称算法运算类函数
// 40. 对称加密
int SDF_Encrypt(void *sesh,
                void *hKeyHandle, unsigned int uiAlgID,
                unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength,
                unsigned char *pucEncData, unsigned int *puiEncDataLength)
{
    unsigned int sizeiv = 16;
    unsigned int len = 8 + 8 + 8 + 4 + sizeiv + uiDataLength;
    unsigned int cmd = 0x8001;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned long *)(sendBuffer + 16)) = htonll((uint64_t)(uintptr_t)hKeyHandle);
    *((unsigned int *)(sendBuffer + 24)) = htonl(uiAlgID);
    memcpy(sendBuffer + 28, pucIV, sizeiv);
    memcpy(sendBuffer + 28 + sizeiv, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucEncData, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiEncDataLength = recv_len;
    }
    return 0;
}

// 41. 对称解密
int SDF_Decrypt(void *sesh,
                void *hKeyHandle, unsigned int uiAlgID,
                unsigned char *pucIV, unsigned char *pucEncData, unsigned int uiEncDataLength,
                unsigned char *pucData, unsigned int *puiDataLength)
{
    unsigned int sizeiv = 16;
    unsigned int len = 8 + 8 + 8 + 4 + sizeiv + uiEncDataLength;
    unsigned int cmd = 0x8002;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned long *)(sendBuffer + 16)) = htonll((uint64_t)(uintptr_t)hKeyHandle);
    *((unsigned int *)(sendBuffer + 24)) = htonl(uiAlgID);
    memcpy(sendBuffer + 28, pucIV, sizeiv);
    memcpy(sendBuffer + 28 + sizeiv, pucEncData, uiEncDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucData, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiDataLength = recv_len;
    }
    return 0;
}

// 42. 计算ＭＡＣ
int SDF_CalculateMAC(void *sesh,
                     void *hKeyHandle, unsigned int uiAlgID,
                     unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength,
                     unsigned char *pucMAC, unsigned int *puiMACLength)
{
    unsigned int sizeiv = 16;
    unsigned int len = 8 + 8 + 8 + 4 + sizeiv + uiDataLength;
    unsigned int cmd = 0x8003;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned long *)(sendBuffer + 16)) = htonll((uint64_t)(uintptr_t)hKeyHandle);
    *((unsigned int *)(sendBuffer + 24)) = htonl(uiAlgID);
    memcpy(sendBuffer + 28, pucIV, sizeiv);
    memcpy(sendBuffer + 28 + sizeiv, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucMAC, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiMACLength = recv_len;
    }
    return 0;
}

// 杂凑运算类函数
// 43. 杂凑运算初始化
int SDF_HashInit(void *sesh,
                 unsigned int uiAlgID,
                 ECCrefPublicKey *pucPublicKey, unsigned char *pucID, unsigned int uiIDLength)
{
    unsigned int len = 8 + 8;
    if (pucPublicKey != NULL)
    {
        len += sizeof(ECCrefPublicKey) + uiIDLength;
    }
    unsigned int cmd = 0x9001;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    if (pucPublicKey != NULL)
    {
        *((unsigned int *)(sendBuffer + 16)) = htonl(pucPublicKey->bits);
        memcpy(sendBuffer + 20, pucPublicKey->x, ECCref_MAX_LEN);
        memcpy(sendBuffer + 20 + ECCref_MAX_LEN, pucPublicKey->y, ECCref_MAX_LEN);
        memcpy(sendBuffer + 20 + ECCref_MAX_LEN * 2, pucID, uiIDLength);
    }

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 44. 多包杂凑运算
int SDF_HashUpdate(void *sesh,
                   unsigned char *pucData, unsigned int uiDataLength)
{
    unsigned int len = 8 + 8 + uiDataLength;
    unsigned int cmd = 0x9002;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    memcpy(sendBuffer + 16, pucData, uiDataLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 45. 杂凑运算结束
int SDF_HashFinal(void *sesh,
                  unsigned char *pucHash, unsigned int *puiHashLength)
{
    unsigned int len = 8 + 8;
    unsigned int cmd = 0x9003;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucHash, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiHashLength = recv_len;
    }
    return 0;
}

// 用户文件操作类函数
// 46. 创建文件
int SDF_CreateFile(void *sesh,
                   unsigned char *pucFileName, unsigned int uiNameLen,
                   unsigned int uiFileSize)
{
    unsigned int len = 8 + 8 + uiNameLen;
    unsigned int cmd = 0xA001;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    memcpy(sendBuffer + 16, pucFileName, uiNameLen);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    return recv_ret;
}

// 47. 读取文件
int SDF_ReadFile(void *sesh,
                 unsigned char *pucFileName, unsigned int uiNameLen,
                 unsigned int uiOffset,
                 unsigned int *puiReadLength, unsigned char *pucBuffer)
{
    unsigned int len = 8 + 8 + 4 + 4 + uiNameLen;
    unsigned int cmd = 0xA002;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiOffset);
    *((unsigned int *)(sendBuffer + 20)) = htonl(*puiReadLength);
    memcpy(sendBuffer + 24, pucFileName, uiNameLen);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    if (recv_ret != 0)
        return recv_ret;
    else
    {
        if (recv(upca->conn, pucBuffer, recv_len, 0) != recv_len)
            return SDR_UNKNOWERR;
        *puiReadLength = recv_len;
    }
    return 0;
}

// 48. 写文件
int SDF_WriteFile(void *sesh,
                  unsigned char *pucFileName, unsigned int uiNameLen,
                  unsigned int uiOffset,
                  unsigned int uiWriteLength, unsigned char *pucBuffer)
{
    unsigned int len = 8 + 8 + 4 + 4 + uiNameLen + uiWriteLength;
    unsigned int cmd = 0xA003;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    *((unsigned int *)(sendBuffer + 16)) = htonl(uiOffset);
    *((unsigned int *)(sendBuffer + 20)) = htonl(uiNameLen);
    memcpy(sendBuffer + 24, pucFileName, uiNameLen);
    memcpy(sendBuffer + 24 + uiNameLen, pucBuffer, uiWriteLength);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_ret = ntohl(*((unsigned int *)(readBuffer + 4)));
    return recv_ret;
}

// 49. 删除文件
int SDF_DeleteFile(void *sesh,
                   unsigned char *pucFileName, unsigned int uiNameLen)
{
    unsigned int len = 8 + 8 + uiNameLen;
    unsigned int cmd = 0xA004;
    cst *upca = (cst *)sesh;
    unsigned char sendBuffer[len];
    char readBuffer[8];
    int recv_ret;
    int recv_len;

    *((unsigned int *)sendBuffer) = htonl(len);
    *((unsigned int *)(sendBuffer + 4)) = htonl(cmd);
    *((unsigned long *)(sendBuffer + 8)) = htonll((uint64_t)(uintptr_t)upca->sesh);
    memcpy(sendBuffer + 16, pucFileName, uiNameLen);

    if (send(upca->conn, sendBuffer, len, 0) != len)
        return SDR_UNKNOWERR;

    if (recv(upca->conn, readBuffer, 8, 0) != 8)
        return SDR_UNKNOWERR;

    recv_len = ntohl(*((unsigned int *)(readBuffer))) - 8;
    return recv_ret;
}
