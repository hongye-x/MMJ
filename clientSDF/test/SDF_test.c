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

#define NUM_THREADS 16

int test()
{
    unsigned int ret;
    void *devh;
    void *sesh;
    int i;
    ret = SDF_OpenSession(devh, &sesh);
    if (ret != 0)
    {
        printf("SDF_OpenSession Error ret = %08X\n", ret);
        return 0;
    }

    DEVICEINFO devhif;
    ret = SDF_GetDeviceInfo(sesh, &devhif);
    if (ret != 0)
    {
        printf("SDF_GetDeviceInfo Error ret = %08X\n", ret);
        return 0;
    }
    // else
    //     printf("devhif :\n%s\n%s\n%d\n", devhif.DeviceName, devhif.DeviceSerial, devhif.BufferSize);

    int randlen = 32;
    unsigned char rand[randlen];
    ret = SDF_GenerateRandom(sesh, randlen, rand);
    if (ret != 0)
    {
        printf("SDF_GenerateRandom Error ret = %08X\n", ret);
        return 0;
    }
    // else
    // {
    //     for (i = 0; i < randlen; i++)
    //         printf("%d,", rand[i]);
    // }
    // printf("\n");

    ret = SDF_GetPrivateKeyAccessRight(sesh, 13, "aabbccaa", 8);
    if (ret != 0)
    {
        printf("SDF_GetPrivateKeyAccessRight Error ret = %08X\n", ret);
        return 0;
    }

    // RSArefPublicKey rsasigpk;
    // ret = SDF_ExportSignPublicKey_RSA(sesh, 13, &rsasigpk);
    // if (ret != 0)
    // {
    //     printf("SDF_ExportSignPublicKey_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // // else
    // // printf("rsasigpk.bits = %d\n", rsasigpk.bits);

    // RSArefPublicKey rsaencpk;
    // ret = SDF_ExportEncPublicKey_RSA(sesh, 13, &rsaencpk);
    // if (ret != 0)
    // {
    //     printf("SDF_ExportEncPublicKey_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // else
    // printf("rsaencpk.bits = %d\n", rsasigpk.bits);

    // RSArefPublicKey *rsapubk = malloc(sizeof(RSArefPublicKey));
    // RSArefPrivateKey *rsapivk = malloc(sizeof(RSArefPrivateKey));
    // ret = SDF_GenerateKeyPair_RSA(sesh, 2048, rsapubk, rsapivk);
    // if (ret != 0)
    // {
    //     printf("SDF_GenerateKeyPair_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // printf("rsapubk.bits = %d\n", rsapubk->bits);
    // printf("rsapivk.bits = %d\n", rsapivk->bits);

    // printf("rsam:\n");
    // for (i = 0; i < 512; i++)
    //     printf("%d,", rsapubk.m[i]);
    // printf("\n");
    // printf("rsae:\n");
    // for (i = 0; i < 512; i++)
    //     printf("%d,", rsapubk.e[i]);
    // printf("\n");
    // printf("rsam:\n");
    // for (i = 0; i < 512; i++)
    //     printf("%d,", rsapivk.m[i]);
    // printf("\n");
    // printf("rsae:\n");
    // for (i = 0; i < 512; i++)
    //     printf("%d,", rsapivk.e[i]);
    // printf("\n");
    // printf("rsad:\n");
    // for (i = 0; i < 512; i++)
    //     printf("%d,", rsapivk.d[i]);
    // printf("\n");
    // printf("rsap0:\n");
    // for (i = 0; i < 256; i++)
    //     printf("%d,", rsapivk.prime[0][i]);
    // printf("\n");
    // printf("rsap1:\n");
    // for (i = 0; i < 256; i++)
    //     printf("%d,", rsapivk.prime[1][i]);
    // printf("\n");
    // printf("rsadp0:\n");
    // for (i = 0; i < 256; i++)
    //     printf("%d,", rsapivk.pexp[0][i]);
    // printf("\n");
    // printf("rsadp1:\n");
    // for (i = 0; i < 256; i++)
    //     printf("%d,", rsapivk.pexp[1][i]);
    // printf("\n");
    // printf("rsacoef:\n");
    // for (i = 0; i < 256; i++)
    //     printf("%d,", rsapivk.coef[i]);
    // printf("\n");

    ////////////////////////////////////////////////////////////////////////////////

    unsigned char grk256[256];
    unsigned int grklen;
    void *grkh = NULL;

    // ret = SDF_GenerateKeyWithIPK_RSA(sesh, 9, 256, grk256, &grklen, &grkh);
    // if (ret != 0)
    // {
    //     printf("SDF_GenerateKeyWithIPK_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // ret = SDF_DestroyKey(sesh, grkh);
    // if (ret != 0)
    // {
    //     printf("SDF_DestroyKey Error ret = %08X\n", ret);
    //     return 0;
    // }
    // for (i = 0; i < grklen; i++)
    // printf("%d,", grk256[i]);
    // printf("\n");

    // ret = SDF_GenerateKeyWithEPK_RSA(sesh, 256, &rsapubk, grk256, &grklen, &grkh);
    // if (ret != 0)
    //     printf("SDF_GenerateKeyWithIPK_RSA Error ret = %08X\n", ret);
    // for (i = 0; i < grklen; i++)
    //     printf("%d,", grk256[i]);
    // printf("\n");

    // void *grkh2 = NULL;
    // ret = SDF_ImportKeyWithISK_RSA(sesh, 9, grk256, grklen, &grkh2);
    // if (ret != 0)
    // {
    //     printf("SDF_ImportKeyWithISK_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // ret = SDF_DestroyKey(sesh, grkh2);
    // if (ret != 0)
    // {
    //     printf("SDF_DestroyKey Error ret = %08X\n", ret);
    //     return 0;
    // }
    // for (i = 0; i < grklen; i++)
    //     printf("%d,", grk256[i]);
    // printf("\n");
    ////////////////////////////////////////////////////////////////////////////////

    // unsigned int rsaindatalen = 256;
    // unsigned char rsaindata[rsaindatalen];
    // memset(rsaindata, 'A', rsaindatalen);
    // unsigned int rsaoutdatalen = 0;
    // unsigned char rsaoutdata[256];
    // ret = SDF_ExternalPublicKeyOperation_RSA(sesh, rsapubk, rsaindata, rsaindatalen,
    //                                          rsaoutdata, &rsaoutdatalen);
    // if (ret != 0)
    // {
    //     printf("SDF_ExternalPublicKeyOperation_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }

    // unsigned int deceddatalen = 0;
    // unsigned char deceddata[256];

    // ret = SDF_ExternalPrivateKeyOperation_RSA(sesh, rsapivk,
    //                                           rsaoutdata, rsaoutdatalen, deceddata, &deceddatalen);
    // if (ret != 0)
    // {
    //     printf("SDF_ExternalPrivateKeyOperation_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // // printf("%s\n", deceddata);

    // ret = SDF_InternalPublicKeyOperation_RSA(sesh, 9, rsaindata, rsaindatalen,
    //                                          rsaoutdata, &rsaoutdatalen);
    // if (ret != 0)
    // {
    //     printf("SDF_InternalPublicKeyOperation_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }

    // ret = SDF_InternalPrivateKeyOperation_RSA(sesh, 9,
    //                                           rsaoutdata, rsaoutdatalen, deceddata, &deceddatalen);
    // if (ret != 0)
    // {
    //     printf("SDF_InternalPrivateKeyOperation_RSA Error ret = %08X\n", ret);
    //     return 0;
    // }
    // // printf("%s\n", deceddata);

    ////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////
    ECCrefPublicKey epk;
    ret = SDF_ExportEncPublicKey_ECC(sesh, 13, &epk);
    if (ret != 0)
    {
        printf("SDF_ExportEncPublicKey_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_ExportSignPublicKey_ECC(sesh, 13, &epk);
    if (ret != 0)
    {
        printf("SDF_ExportSigPublicKey_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ECCrefPublicKey *eccpubk1 = malloc(sizeof(ECCrefPublicKey));
    ECCrefPrivateKey *eccpivk1 = malloc(sizeof(ECCrefPrivateKey));
    ret = SDF_GenerateKeyPair_ECC(sesh, SGD_SM2, 256, eccpubk1, eccpivk1);
    if (ret != 0)
    {
        printf("SDF_GenerateKeyPair_ECC Error ret = %08X\n", ret);
        return 0;
    }
    // for (i = 0; i < 64; i++)
    //     printf("%d,", (unsigned char)eccpubk1.x[i]);
    // printf("\n");
    // for (i = 0; i < 64; i++)
    //     printf("%d,", (unsigned char)eccpubk1.y[i]);
    // printf("\n");

    // for (i = 0; i < 64; i++)
    //     printf("%d,", (unsigned char)eccpivk1.K[i]);
    // printf("\n");

    unsigned char orgdigest[32];
    memset(orgdigest, 'B', 32);
    ECCSignature eccsig;
    ret = SDF_ExternalSign_ECC(sesh, SGD_SM2, eccpivk1, orgdigest, 32, &eccsig);
    if (ret != 0)
    {
        printf("SDF_ExternalSign_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_ExternalVerify_ECC(sesh, SGD_SM2, eccpubk1, orgdigest, 32, &eccsig);
    if (ret != 0)
    {
        printf("SDF_ExternalVerify_ECC Error ret = %08X\n", ret);
        return 0;
    }

    // ret = SDF_ReleasePrivateKeyAccessRight(sesh, 13);
    // if (ret != 0)
    // {
    //     printf("SDF_ReleasePrivateKeyAccessRight Error ret = %08X\n", ret);
    //     return 0;
    // }
    ret = SDF_InternalSign_ECC(sesh, 13, orgdigest, 32, &eccsig);
    if (ret != 0)
    {
        printf("SDF_InternalSign_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_InternalVerify_ECC(sesh, 13, orgdigest, 32, &eccsig);
    if (ret != 0)
    {
        printf("SDF_InternalVerify_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ECCCipher eccip;
    ret = SDF_ExternalEncrypt_ECC(sesh, SGD_SM2, eccpubk1, orgdigest, 32, &eccip);
    if (ret != 0)
    {
        printf("SDF_ExternalEncrypt_ECC Error ret = %08X\n", ret);
        return 0;
    }
    // for (i = 0; i < 64; i++)
    //     printf("%d,", (unsigned char)eccip.x[i]);
    // printf("\n");
    // for (i = 0; i < 64; i++)
    //     printf("%d,", (unsigned char)eccip.y[i]);
    // printf("\n");
    // for (i = 0; i < 32; i++)
    //     printf("%d,", (unsigned char)eccip.M[i]);
    // printf("\n");
    // for (i = 0; i < 136; i++)
    //     printf("%d,", (unsigned char)eccip.C[i]);
    // printf("\n");
    // printf("%d", eccip.L);
    unsigned int decdatalen = 0;
    unsigned char decdata[136];
    ret = SDF_ExternalDecrypt_ECC(sesh, SGD_SM2, eccpivk1, &eccip, decdata, &decdatalen);
    if (ret != 0)
    {
        printf("SDF_ExternalDecrypt_ECC Error ret = %08X\n", ret);
        return 0;
    }

    void *eckh;
    ret = SDF_GenerateKeyWithIPK_ECC(sesh, 13, 256, &eccip, &eckh);
    if (ret != 0)
    {
        printf("SDF_GenerateKeyWithIPK_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ECCCipher eccip2;
    // ret = SDF_ExchangeDigitEnvelopeBaseOnECC(sesh, 13, SGD_SM2, eccpubk1, &eccip, &eccip2);
    // if (ret != 0)
    // {
    //     printf("SDF_ExchangeDigitEnvelopeBaseOnECC Error ret = %08X\n", ret);
    //     return 0;
    // }
    // ret = SDF_GenerateKeyWithEPK_ECC(sesh, 256, SGD_SM2, eccpubk1, &eccip, &eckh);
    // if (ret != 0)
    //     printf("SDF_GenerateKeyWithEPK_ECC Error ret = %08X\n", ret);

    ret = SDF_DestroyKey(sesh, eckh);
    if (ret != 0)
    {
        printf("SDF_DestroyKey Error ret = %08X\n", ret);
        return 0;
    }

    void *eckh2;
    ret = SDF_ImportKeyWithISK_ECC(sesh, 13, &eccip, &eckh2);
    if (ret != 0)
    {
        printf("SDF_ImportKeyWithISK_ECC Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_DestroyKey(sesh, eckh2);
    if (ret != 0)
    {
        printf("SDF_DestroyKey Error ret = %08X\n", ret);
        return 0;
    }

    unsigned int ekeylen = 32;
    unsigned char ekey[ekeylen];
    void *keyh;
    ret = SDF_GenerateKeyWithKEK(sesh, 256, SGD_SMS4_ECB, 13, ekey, &ekeylen, &keyh);
    if (ret != 0)
    {
        printf("SDF_GenerateKeyWithKEK Error ret = %08X\n", ret);
        return 0;
    }

    void *keyh2;
    ret = SDF_ImportKeyWithKEK(sesh, SGD_SMS4_ECB, 13, ekey, ekeylen, &keyh2);
    if (ret != 0)
    {
        printf("SDF_ImportKeyWithKEK Error ret = %08X\n", ret);
        return 0;
    }

    unsigned char iv[16];
    memset(iv, '5', 16);
    unsigned char mdata[32];
    memset(mdata, '8', 32);
    unsigned char emdata[32];
    unsigned int emdatalen;
    unsigned char demdata[32];
    unsigned int demdatalen;
    ret = SDF_Encrypt(sesh, keyh, SGD_SMS4_CBC, iv, mdata, 32, emdata, &emdatalen);
    if (ret != 0)
    {
        printf("SDF_Encrypt Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_Decrypt(sesh, keyh2, SGD_SMS4_CBC, iv, emdata, 32, demdata, &demdatalen);
    if (ret != 0)
    {
        printf("SDF_Decrypt Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_DestroyKey(sesh, keyh);
    if (ret != 0)
    {
        printf("SDF_DestroyKey Error ret = %08X\n", ret);
        return 0;
    }
    ret = SDF_DestroyKey(sesh, keyh2);
    if (ret != 0)
    {
        printf("SDF_DestroyKey Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_HashInit(sesh, 1, eccpubk1, "abcdefgh", 8);
    if (ret != 0)
    {
        printf("SDF_HashInit Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_HashUpdate(sesh, mdata, 32);
    if (ret != 0)
    {
        printf("SDF_HashUpdate Error ret = %08X\n", ret);
        return 0;
    }

    unsigned char digest[32];
    unsigned int diglen;
    ret = SDF_HashFinal(sesh, digest, &diglen);
    if (ret != 0)
    {
        printf("SDF_HashFinal Error ret = %08X\n", ret);
        return 0;
    }

    ret = SDF_CloseSession(sesh);
    if (ret != 0)
    {
        printf("SDF_CloseSession Error ret = %08X\n", ret);
        return 0;
    }

    return 0;
}

int main()
{
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;
    for (t = 0; t < NUM_THREADS; t++)
    {
        rc = pthread_create(&threads[t], NULL, (void *)test, NULL);
        if (rc)
        {
            printf("ERROR; return code from pthread_create() is %d\n", rc);
            return -1;
        }
    }

    // 等待所有线程完成
    for (t = 0; t < NUM_THREADS; t++)
    {
        pthread_join(threads[t], NULL);
    }

    printf("All threads completed.\n");
    return 0;
}