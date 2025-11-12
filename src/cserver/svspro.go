package main

/*
#cgo CFLAGS:
#cgo LDFLAGS:

#include <string.h>
#include <stdint.h>

#define ROL32(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

#define GETU32(p) \
	((uint32_t)(p)[0] << 24 | \
	 (uint32_t)(p)[1] << 16 | \
	 (uint32_t)(p)[2] <<  8 | \
	 (uint32_t)(p)[3])

#define PUTU32(p,V) \
	 ((p)[0] = (uint8_t)((V) >> 24), \
	  (p)[1] = (uint8_t)((V) >> 16), \
	  (p)[2] = (uint8_t)((V) >>  8), \
	  (p)[3] = (uint8_t)(V))



#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x) ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z))

#define SM3_DIGEST_SIZE		32
#define SM3_BLOCK_SIZE		64
#define SM3_STATE_WORDS		8


typedef struct {
	uint32_t digest[SM3_STATE_WORDS];
	uint64_t nblocks;
	uint8_t block[SM3_BLOCK_SIZE];
	size_t num;
} SM3_CTX;


static uint32_t K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

#if ENABLE_SMALL_FOOTPRINT
void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t F;
	uint32_t G;
	uint32_t H;
	uint32_t W[68];
	uint32_t SS1, SS2, TT1, TT2;
	int j;

	while (blocks--) {

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];

		for (j = 0; j < 16; j++) {
			W[j] = GETU32(data + j*4);
		}

		for (; j < 68; j++) {
			W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
				^ ROL32(W[j - 13], 7) ^ W[j - 6];
		}

		for (j = 0; j < 16; j++) {
			SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
			SS2 = SS1 ^ ROL32(A, 12);
			TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = GG00(E, F, G) + H + SS1 + W[j];
			D = C;
			C = ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROL32(F, 19);
			F = E;
			E = P0(TT2);
		}

		for (; j < 64; j++) {
			SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
			SS2 = SS1 ^ ROL32(A, 12);
			TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = GG16(E, F, G) + H + SS1 + W[j];
			D = C;
			C = ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROL32(F, 19);
			F = E;
			E = P0(TT2);
		}

		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;

		data += 64;
	}
}
#else

#define SM3_ROUND_0(j,A,B,C,D,E,F,G,H)			\
	SS0 = ROL32(A, 12);				\
	SS1 = ROL32(SS0 + E + K[j], 7);			\
	SS2 = SS1 ^ SS0;				\
	D += FF00(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG00(E, F, G) + H + W[j];		\
	B = ROL32(B, 9);				\
	H = P0(SS1);					\
	F = ROL32(F, 19);				\
	W[j+16] = P1(W[j] ^ W[j+7] ^ ROL32(W[j+13], 15)) ^ ROL32(W[j+3], 7) ^ W[j+10];

#define SM3_ROUND_1(j,A,B,C,D,E,F,G,H)			\
	SS0 = ROL32(A, 12);				\
	SS1 = ROL32(SS0 + E + K[j], 7);			\
	SS2 = SS1 ^ SS0;				\
	D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG16(E, F, G) + H + W[j];		\
	B = ROL32(B, 9);					\
	H = P0(SS1);					\
	F = ROL32(F, 19);				\
	W[j+16] = P1(W[j] ^ W[j+7] ^ ROL32(W[j+13], 15)) ^ ROL32(W[j+3], 7) ^ W[j+10];


#define SM3_ROUND_2(j,A,B,C,D,E,F,G,H)			\
	SS0 = ROL32(A, 12);				\
	SS1 = ROL32(SS0 + E + K[j], 7);			\
	SS2 = SS1 ^ SS0;				\
	D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG16(E, F, G) + H + W[j];		\
	B = ROL32(B, 9);				\
	H = P0(SS1);					\
	F = ROL32(F, 19);

void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t F;
	uint32_t G;
	uint32_t H;
	uint32_t W[68];
	uint32_t SS0, SS1, SS2;
	int j;

	while (blocks--) {

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];

		for (j = 0; j < 16; j++) {
			W[j] = GETU32(data + j*4);
		}

		SM3_ROUND_0( 0, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 1, D,A,B,C, H,E,F,G);
		SM3_ROUND_0( 2, C,D,A,B, G,H,E,F);
		SM3_ROUND_0( 3, B,C,D,A, F,G,H,E);
		SM3_ROUND_0( 4, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 5, D,A,B,C, H,E,F,G);
		SM3_ROUND_0( 6, C,D,A,B, G,H,E,F);
		SM3_ROUND_0( 7, B,C,D,A, F,G,H,E);
		SM3_ROUND_0( 8, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 9, D,A,B,C, H,E,F,G);
		SM3_ROUND_0(10, C,D,A,B, G,H,E,F);
		SM3_ROUND_0(11, B,C,D,A, F,G,H,E);
		SM3_ROUND_0(12, A,B,C,D, E,F,G,H);
		SM3_ROUND_0(13, D,A,B,C, H,E,F,G);
		SM3_ROUND_0(14, C,D,A,B, G,H,E,F);
		SM3_ROUND_0(15, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(16, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(17, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(18, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(19, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(20, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(21, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(22, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(23, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(24, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(25, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(26, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(27, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(28, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(29, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(30, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(31, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(32, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(33, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(34, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(35, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(36, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(37, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(38, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(39, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(40, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(41, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(42, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(43, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(44, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(45, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(46, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(47, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(48, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(49, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(50, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(51, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(52, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(53, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(54, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(55, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(56, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(57, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(58, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(59, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(60, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(61, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(62, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(63, B,C,D,A, F,G,H,E);

		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;

		data += 64;
	}
}
#endif

void sm3_init(SM3_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;
}

void sm3_resetctx(SM3_CTX *ctx, uint8_t *midhash)
{
	memset(ctx, 0, sizeof(*ctx));
	int i;
	for (i = 0; i < 8; i++) {
		ctx->digest[i] = GETU32(midhash + i*4);
	}
}


void sm3_update(SM3_CTX *ctx, unsigned char *data, int data_len)
{
	size_t blocks;
	ctx->num &= 0x3f;
	if (ctx->num) {
		size_t left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress_blocks(ctx->digest, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

	blocks = data_len / SM3_BLOCK_SIZE;
	if (blocks) {
		sm3_compress_blocks(ctx->digest, data, blocks);
		ctx->nblocks += blocks;
		data += SM3_BLOCK_SIZE * blocks;
		data_len -= SM3_BLOCK_SIZE * blocks;
	}

	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_finish(SM3_CTX *ctx, unsigned char *digest)
{
	int i;

	ctx->num &= 0x3f;
	ctx->block[ctx->num] = 0x80;

	if (ctx->num <= SM3_BLOCK_SIZE - 9) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress_blocks(ctx->digest, ctx->block, 1);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));
	sm3_compress_blocks(ctx->digest, ctx->block, 1);

	for (i = 0; i < 8; i++) {
		PUTU32(digest + i*4, ctx->digest[i]);
	}
}
*/
import "C"

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"sig_vfy/src/base"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	ISV "sig_vfy/src/sigvfy"
	a1 "sig_vfy/src/sigvfy/sv0029_asn1"
	"time"

	"github.com/tjfoc/gmsm/x509"
)

func sendErrorMsgBackSV(conn net.Conn, rsptype, uiret int) {
	var rtmsg []byte
	rspb := a1.NewSVSRespondBuilder()
	switch rsptype {
	case a1.ReqType_ExportCert:
		d, _ := rspb.BuildExportCertRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_ParseCert:
		d, _ := rspb.BuildParseCertRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_ValidateCert:
		d, _ := rspb.BuildValidateCertRespond(uiret, 0)
		rtmsg = d

	case a1.ReqType_SignData:
		d, _ := rspb.BuildSignDataRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedData:
		d, _ := rspb.BuildVerifySignedDataRespond(uiret)
		rtmsg = d

	case a1.ReqType_SignDataInit:
		d, _ := rspb.BuildSignDataInitRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_SignDataUpdate:
		d, _ := rspb.BuildSignDataUpdateRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_SignDataFinal:
		d, _ := rspb.BuildSignDataFinalRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedDataInit:
		d, _ := rspb.BuildVerifySignedDataInitRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedDataUpdate:
		d, _ := rspb.BuildSignDataUpdateRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedDataFinal:
		d, _ := rspb.BuildVerifySignedDataFinalRespond(uiret)
		rtmsg = d

	case a1.ReqType_SignMessage:
		d, _ := rspb.BuildSignMessageRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedMessage:
		d, _ := rspb.BuildVerifySignedMessageRespond(uiret)
		rtmsg = d

	case a1.ReqType_SignMessageInit:
		d, _ := rspb.BuildVerifySignedMessageInitRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_SignMessageUpdate:
		d, _ := rspb.BuildSignMessageUpdateRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_SignMessageFinal:
		d, _ := rspb.BuildVerifySignedMessageFinalRespond(uiret)
		rtmsg = d

	case a1.ReqType_VerifySignedMessageInit:
		d, _ := rspb.BuildVerifySignedMessageInitRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedMessageUpdate:
		d, _ := rspb.BuildVerifySignedMessageUpdateRespond(uiret, nil)
		rtmsg = d

	case a1.ReqType_VerifySignedMessageFinal:
		d, _ := rspb.BuildVerifySignedMessageFinalRespond(uiret)
		rtmsg = d
	}
	if conn != nil {
		conn.Write(rtmsg)
	}
}

func ParsClientMsgAndSend_SVS(conn net.Conn) *b.StdErr {
	timeoutDuration := 5 * time.Second //5s
	conn.SetDeadline(time.Now().Add(timeoutDuration))

	var msg = make([]byte, b.RECVMAXLEN_ONCE/1024) // 16K
	reader := bufio.NewReader(conn)
	for {
		rdlen, err := reader.Read(msg)
		if err != nil {
			conn.Close()
			return nil
		}
		if rdlen < 8 {
			return nil
		}

		sttype, bst, err := a1.ParseRequest(msg[:rdlen])
		if err == nil {
			switch sttype {
			case a1.ReqType_ExportCert:
				ist := bst.(*a1.Request_ExportCert_2)
				sExportCert(conn, ist)
			case a1.ReqType_ParseCert:
				ist := bst.(*a1.Request_ParseCert_2)
				sParseCert(conn, ist)
			case a1.ReqType_ValidateCert:
				ist := bst.(*a1.Request_ValidateCert_2)
				sValidateCert(conn, ist)
			case a1.ReqType_SignData:
				ist := bst.(*a1.Request_SignData_2)
				sSignData(conn, ist)
			case a1.ReqType_VerifySignedData:
				ist := bst.(*a1.Request_VerifySignedData_2)
				sVerifySignedData(conn, ist)
			case a1.ReqType_SignDataInit:
				ist := bst.(*a1.Request_SignDataInit_2)
				sSignDataInit(conn, ist)
			case a1.ReqType_SignDataUpdate:
				ist := bst.(*a1.Request_SignDataUpdate_2)
				sSignDataUpdate(conn, ist)
			case a1.ReqType_SignDataFinal:
				ist := bst.(*a1.Request_SignDataFinal_2)
				sSignDataFinal(conn, ist)
			case a1.ReqType_VerifySignedDataInit:
				ist := bst.(*a1.Request_VerifySignedDataInit_2)
				sVerifySignedDataInit(conn, ist)
			case a1.ReqType_VerifySignedDataUpdate:
				ist := bst.(*a1.Request_VerifySignedDataUpdate_2)
				sVerifySignedDataUpdate(conn, ist)
			case a1.ReqType_VerifySignedDataFinal:
				ist := bst.(*a1.Request_VerifySignedDataFinal_2)
				sVerifySignedDataFinal(conn, ist)
			case a1.ReqType_SignMessage:
				ist := bst.(*a1.Request_SignMessage_2)
				sSignMessage(conn, ist)
			case a1.ReqType_VerifySignedMessage:
				ist := bst.(*a1.Request_VerifySignedMessage_2)
				sVerifySignedMessage(conn, ist)
			case a1.ReqType_SignMessageInit:
				ist := bst.(*a1.Request_SignMessageInit_2)
				sSignMessageInit(conn, ist)
			case a1.ReqType_SignMessageUpdate:
				ist := bst.(*a1.Request_SignMessageUpdate_2)
				sSignMessageUpdate(conn, ist)
			case a1.ReqType_SignMessageFinal:
				ist := bst.(*a1.Request_SignMessageFinal_2)
				sSignMessageFinal(conn, ist)
			case a1.ReqType_VerifySignedMessageInit:
				ist := bst.(*a1.Request_VerifySignedMessageInit_2)
				sVerifySignedMessageInit(conn, ist)
			case a1.ReqType_VerifySignedMessageUpdate:
				ist := bst.(*a1.Request_VerifySignedMessageUpdate_2)
				sVerifySignedMessageUpdate(conn, ist)
			case a1.ReqType_VerifySignedMessageFinal:
				ist := bst.(*a1.Request_VerifySignedMessageFinal_2)
				sVerifySignedMessageFinal(conn, ist)
			default:
				sendErrorMsgBack(conn, uint(b.UNKNOW_CMD))
			}
		} else {
			return b.CreateStdErr(b.ASN1TYPE_ERROR,
				"Non ASN1 Type Code[%08X]", b.ASN1TYPE_ERROR)
		}
	}
}

// ExportCert
func sExportCert(conn net.Conn, st *a1.Request_ExportCert_2) *b.StdErr { // 标识用idx替代
	var rtmsg []byte
	rspb := a1.NewSVSRespondBuilder()
	iidf := (string(st.Identification))
	var backret int = 0

	if ISV.GAppCertInfo[iidf] == nil {
		backret = b.GM_ERROR_CERT_ID
		sendErrorMsgBackSV(conn, a1.ReqType_ExportCert, backret)
		return b.CreateStdErr(backret,
			"Export Cert BuildExportCertRespond Error Code[%08X]", backret)
	} else {
		if ISV.GAppCertInfo[iidf].CertPem == nil {
			backret = b.GM_ERROR_CERT_ID
			sendErrorMsgBackSV(conn, a1.ReqType_ExportCert, backret)
			return b.CreateStdErr(backret,
				"Export Cert BuildExportCertRespond Error Code[%08X]", backret)
		}
	}

	block, _ := pem.Decode(ISV.GAppCertInfo[iidf].CertPem)
	prtmsg, _ := rspb.BuildExportCertRespond(backret, block.Bytes)
	rtmsg = prtmsg
	conn.Write(rtmsg)
	return nil
}

// ParseCert
func sParseCert(conn net.Conn, st *a1.Request_ParseCert_2) *b.StdErr { // 标识用idx替代
	var rtmsg []byte
	var binfo []byte
	x509usercert, stderr := ISV.ParseCert2_x509(st.Cert.Bytes)
	if stderr != nil {
		sendErrorMsgBackSV(conn, a1.ReqType_ParseCert, b.GM_ERROR_CERT_DECODE)
		return stderr
	}
	switch st.InfoType {
	// 基础证书字段
	case a1.SGD_CERT_VERSION:
		binfo, _ = a1.Marshal(a1.CertT_Version{Version: x509usercert.Version})
	case a1.SGD_CERT_SERIAL:
		binfo, _ = a1.Marshal(a1.CertT_Serial{Number: x509usercert.SerialNumber.Bytes()})
	case a1.SGD_CERT_ISSUER:
		binfo, _ = a1.Marshal(a1.CertT_Issuer{Raw: x509usercert.RawIssuer})
	case a1.SGD_CERT_VALID_TIME:
		binfo, _ = a1.Marshal(a1.CertT_Validity{
			NotBefore: x509usercert.NotBefore.UTC(),
			NotAfter:  x509usercert.NotAfter.UTC(),
		})
	case a1.SGD_CERT_SUBJECT:
		binfo, _ = a1.Marshal(a1.CertT_Subject{Raw: x509usercert.RawSubject})
	case a1.SGD_CERT_DER_PUBLIC_KEY:
		binfo, _ = a1.Marshal(a1.CertT_PubKey{Raw: x509usercert.RawSubjectPublicKeyInfo})
	// 证书扩展项
	case a1.SGD_CERT_DER_EXTENSIONS:
		rawExts, _ := a1.Marshal(x509usercert.Extensions)
		binfo, _ = a1.Marshal(a1.CertT_Extensions{Raw: rawExts})
	case a1.SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO:
		binfo, _ = a1.Marshal(a1.CertT_AuthKeyID{ID: x509usercert.AuthorityKeyId})
	case a1.SGD_EXT_SUBJECTKEYIDENTIFIER_INFO:
		binfo, _ = a1.Marshal(a1.CertT_SubjKeyID{ID: x509usercert.SubjectKeyId})
	case a1.SGD_EXT_KEYUSAGE_INFO:
		binfo, _ = a1.Marshal(a1.CertT_KeyUsage{Bits: a1.Bs{
			Bytes:     []byte{byte(x509usercert.KeyUsage), byte(x509usercert.KeyUsage >> 8)},
			BitLength: 16,
		}})
	case a1.SGD_EXT_BASICCONSTRAINTS_INFO:
		binfo, _ = a1.Marshal(a1.CertT_BasicConstraints{
			IsCA:       x509usercert.IsCA,
			MaxPathLen: x509usercert.MaxPathLen,
		})
	case a1.SGD_EXT_EXTKEYUSAGE_INFO:
		// 转换ExtKeyUsage到OID列表
		var oids []int
		for _, eku := range x509usercert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageAny:
				oids = append(oids, []int{2, 5, 29, 37, 0}...)
			case x509.ExtKeyUsageServerAuth:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 1}...)
			case x509.ExtKeyUsageClientAuth:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 2}...)
			case x509.ExtKeyUsageCodeSigning:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 3}...)
			case x509.ExtKeyUsageEmailProtection:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 4}...)
			case x509.ExtKeyUsageIPSECEndSystem:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 5}...)
			case x509.ExtKeyUsageIPSECTunnel:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 6}...)
			case x509.ExtKeyUsageIPSECUser:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 7}...)
			case x509.ExtKeyUsageTimeStamping:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 8}...)
			case x509.ExtKeyUsageOCSPSigning:
				oids = append(oids, []int{1, 3, 6, 1, 5, 5, 7, 3, 9}...)
			case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
				oids = append(oids, []int{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}...)
			case x509.ExtKeyUsageNetscapeServerGatedCrypto:
				oids = append(oids, []int{2, 16, 840, 1, 113730, 4, 1}...)
			default:
				continue
			}
		}
		binfo, _ = a1.Marshal(a1.CertT_ExtKeyUsage{OIDs: oids})
	// 颁发者/主题详细信息
	case a1.SGD_CERT_ISSUER_CN:
		binfo, _ = a1.Marshal(a1.CertT_IssuerCN{CN: x509usercert.Issuer.CommonName})
	case a1.SGD_CERT_ISSUER_O:
		binfo, _ = a1.Marshal(a1.CertT_IssuerO{O: x509usercert.Issuer.Organization[0]})
	case a1.SGD_CERT_SUBJECT_CN:
		binfo, _ = a1.Marshal(a1.CertT_SubjectCN{CN: x509usercert.Subject.CommonName})
	case a1.SGD_CERT_SUBJECT_EMAIL:
		binfo, _ = a1.Marshal(a1.CertT_SubjectEmail{Email: x509usercert.EmailAddresses[0]})
	// 时间字段
	case a1.SGD_CERT_NOTBEFORE_TIME:
		binfo, _ = a1.Marshal(a1.CertT_NotBefore{
			Time: x509usercert.NotBefore.UTC(),
		})
	case a1.SGD_CERT_NOTAFTER_TIME:
		binfo, _ = a1.Marshal(a1.CertT_NotAfter{
			Time: x509usercert.NotAfter.UTC(),
		})
	default:
		sendErrorMsgBackSV(conn, a1.ReqType_ParseCert, b.GM_UNKNOW_CERT_INFO_TYPE)
		return b.CreateStdErr(b.GM_UNKNOW_CERT_INFO_TYPE,
			"UnKnow Cert Info Type Code[%08X]", b.GM_UNKNOW_CERT_INFO_TYPE)
	}
	rspb := a1.NewSVSRespondBuilder()
	prtmsg, _ := rspb.BuildParseCertRespond(0, binfo)
	rtmsg = prtmsg
	conn.Write(rtmsg)
	return nil
}

// ValidateCert
func sValidateCert(conn net.Conn, st *a1.Request_ValidateCert_2) *b.StdErr {
	var rtmsg []byte
	var ocspres int
	x509usercert, stderr := ISV.ParseCert2_x509(st.Cert.Bytes)
	if stderr != nil {
		sendErrorMsgBackSV(conn, a1.ReqType_ValidateCert, b.GM_ERROR_CERT_DECODE)
		return stderr
	}

	stderr = ISV.CheckCertValidity(x509usercert)
	if stderr != nil {
		sendErrorMsgBackSV(conn, a1.ReqType_ValidateCert, b.GM_ERROR_CERT)
		return stderr
	}

	if st.OCSP == true {
		ocspres = b.GM_ERROR_SERVER_CONNECT // ocsp 实现
	}

	rspb := a1.NewSVSRespondBuilder()
	prtmsg, _ := rspb.BuildValidateCertRespond(0, ocspres)
	rtmsg = prtmsg
	conn.Write(rtmsg)
	return nil
}

// SignData
func sSignData(conn net.Conn, st *a1.Request_SignData_2) *b.StdErr {
	var rtmsg []byte
	keyidx := st.KeyIndex*2 - 1 //sign key
	keypin := st.KeyValue
	sigmtd := st.SignMethod
	sigd := st.InData
	var sig [64]byte

	sesh, iret := ISDF.OpenSession(CSDevH)
	if iret != 0 {
		sendErrorMsgBackSV(conn, a1.ReqType_SignData, iret)
		return b.CreateStdErr(iret,
			"Sig Data SDF Func Error Code[%08X]", iret)
	}
	defer ISDF.CloseSession(sesh)

	// get access right
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		sendErrorMsgBackSV(conn, a1.ReqType_SignData, b.SDR_KEYNOTEXIST)
		return b.CreateStdErr(int(b.SDR_KEYNOTEXIST),
			"Sig Data SDF Func Error ret : %08X", b.SDR_KEYNOTEXIST)
	}
	if CSSm2Map[int(keyidx)].PrivKeyAuth == 0 {
	} else {
		pwddig, iret := ISDF.Hash(sesh, keypin)
		if iret != 0 {
			sendErrorMsgBackSV(conn, a1.ReqType_SignData, iret)
			return b.CreateStdErr(iret,
				"Sig Data SDF Func Error Code[%08X]", iret)
		}

		pivpin := CSSm2Map[int(keyidx)].PrivPin
		if bytes.Equal(pwddig, pivpin[:]) {
			RWmu.Lock()
			SM2KeyCanUseList[conn][keyidx] = 1
			SM2KeyCanUseList[conn][keyidx+1] = 1
			RWmu.Unlock()
		} else {
			sendErrorMsgBackSV(conn, a1.ReqType_SignData, b.SDR_PARDENY)
			return b.CreateStdErr(b.SDR_PARDENY,
				"Sig Data SDF Func Error Code[%08X]", b.SDR_PARDENY)
		}
	}
	defer func() {
		SM2KeyCanUseList[conn] = nil
	}()

	if sigmtd == a1.SGD_SM3_RSA || sigmtd == a1.SGD_SM3_SM2 {
		outhash, iret := ISDF.Hash(sesh, sigd)
		if iret != 0 {
			sendErrorMsgBackSV(conn, a1.ReqType_SignData, iret)
			return b.CreateStdErr(iret,
				"Sig Data SDF Func Error Code[%08X]", iret)
		}

		outsig, iret := ISDF.ExternalSignECC(sesh,
			ISDF.SGD_SM2_1, &CSSm2Map[keyidx].PrivKey, outhash)
		if iret != 0 {
			sendErrorMsgBackSV(conn, a1.ReqType_SignData, iret)
			return b.CreateStdErr(iret,
				"Sig Data SDF Func Error Code[%08X]", iret)
		}
		copy(sig[:32], outsig.R[32:])
		copy(sig[32:64], outsig.S[32:])
	} else {
		sendErrorMsgBackSV(conn, a1.ReqType_SignData, b.GM_UNSUPPORT_SIGALT)
		return b.CreateStdErr(iret,
			"Sig Data SDF Func Error Code[%08X]", iret)
	}

	rspb := a1.NewSVSRespondBuilder()
	prtmsg, _ := rspb.BuildSignDataRespond(0, sig[:])
	rtmsg = prtmsg
	conn.Write(rtmsg)
	return nil
}

// VerifySignedData
func sVerifySignedData(conn net.Conn, st *a1.Request_VerifySignedData_2) *b.StdErr {
	var rtmsg []byte
	certserial := st.CertSN.Bytes
	sesh, iret := ISDF.OpenSession(CSDevH)
	if iret != 0 {
		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedData, iret)
		return b.CreateStdErr(iret,
			"Verify Data SDF Func Error Code[%08X]", iret)
	}
	defer ISDF.CloseSession(sesh)

	var appcertinfo *ISV.X509TBSInfo
	if st.Type == 1 {
		appcertinfo1, _, _, stderr := ISV.ParseTBSFromDER(st.Cert.Bytes)
		if stderr != nil {
			sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedData, stderr.Errcode)
			return stderr
		}
		appcertinfo = appcertinfo1
	} else {
		appcertinfo1, _, _, stderr := ISV.ParseTBSFromDER(ISV.GAppCertInfo[string(certserial)].CertPem)
		if stderr != nil {
			sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedData, stderr.Errcode)
			return stderr
		}
		appcertinfo = appcertinfo1
	}

	outhash, iret := ISDF.Hash(sesh, st.InData)
	if iret != 0 {
		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedData, iret)
		return b.CreateStdErr(iret,
			"Verify Data SDF Func Error Code[%08X]", iret)
	}
	bsig, err := a1.Decode_asn1RawSM2Sig_2_bSM2Sig(st.Signature)
	if err != nil {
		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedData,
			b.GM_UNSUPPORT_SIGNATURE_VALUE)
		return b.CreateStdErr(b.GM_UNSUPPORT_SIGNATURE_VALUE,
			"Verify Data Unknow SigData[%08X]", b.GM_UNSUPPORT_SIGNATURE_VALUE)
	}

	var sig ISDF.ECCSignature
	copy(sig.R[32:], bsig[:32])
	copy(sig.S[32:], bsig[32:64])
	iret = ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2_1, &appcertinfo.PublicKey, outhash, &sig)
	if iret != 0 {
		return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	}

	rspb := a1.NewSVSRespondBuilder()
	prtmsg, _ := rspb.BuildVerifySignedDataRespond(0)
	rtmsg = prtmsg
	conn.Write(rtmsg)
	return nil
}

// SignDataInit 需厂家提供hash with ctx的接口
func sSignDataInit(conn net.Conn, st *a1.Request_SignDataInit_2) *b.StdErr {
	// var rtmsg []byte
	// sigmtd := st.SignMethod
	// sigpubk := st.SignerPublicKey
	// signid := st.SignerID
	// sigd := st.InData
	// // sigdl := st.InDataLen
	// var midhash []byte

	// // if sigdl%C.SM3_BLOCK_SIZE != 0 {
	// // 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataInit, b.GM_MULTI_PACKLENTH_ERROR)
	// // 	return b.CreateStdErr(b.GM_MULTI_PACKLENTH_ERROR,
	// // 		"Sig Data Len Error Code[%08X]", b.GM_MULTI_PACKLENTH_ERROR)
	// // }

	// sesh, iret := ISDF.OpenSession(CSDevH)
	// if iret != 0 {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataInit, iret)
	// 	return b.CreateStdErr(iret,
	// 		"Sig Data SDF Func Error Code[%08X]", iret)
	// }
	// defer ISDF.CloseSession(sesh)

	// if sigmtd == a1.SGD_SM3_RSA || sigmtd == a1.SGD_SM3_SM2 {
	// 	var ecpuk ISDF.ECCrefPublicKey
	// 	ecpuk.Bits = 256
	// 	copy(ecpuk.X[32:], sigpubk[:32])
	// 	copy(ecpuk.Y[32:], sigpubk[32:64])
	// 	iret := ISDF.HashInit(sesh, ISDF.SGD_SM3, &ecpuk, signid)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_SignDataInit, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Sig Data SDF Func Error Code[%08X]", iret)
	// 	}

	// 	iret = ISDF.HashUpdate(sesh, sigd)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_SignDataInit, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Sig Data SDF Func Error Code[%08X]", iret)
	// 	}

	// 	outhash, iret := ISDF.HashFinal(sesh)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_SignDataInit, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Sig Data SDF Func Error Code[%08X]", iret)
	// 	}
	// 	midhash = outhash
	// } else {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataInit, b.GM_UNSUPPORT_SIGALT)
	// 	return b.CreateStdErr(b.GM_UNSUPPORT_SIGALT,
	// 		"Sig Data Unsupport SignAlg Code[%08X]", b.GM_UNSUPPORT_SIGALT)
	// }

	// rspb := a1.NewSVSRespondBuilder()
	// prtmsg, _ := rspb.BuildSignDataInitRespond(0, midhash)
	// rtmsg = prtmsg
	// conn.Write(rtmsg)
	return nil
}

// SignDataUpdate 需厂家提供hash with ctx的接口
func sSignDataUpdate(conn net.Conn, st *a1.Request_SignDataUpdate_2) *b.StdErr {
	// var rtmsg []byte
	// sigmtd := st.SignMethod
	// orgmindhash := st.HashVaule
	// sigdn := st.InData
	// sigdnl := st.InDataLen
	// var midhash [32]byte

	// // if sigdnl%C.SM3_BLOCK_SIZE != 0 {
	// // 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataUpdate, b.GM_MULTI_PACKLENTH_ERROR)
	// // 	return b.CreateStdErr(b.GM_MULTI_PACKLENTH_ERROR,
	// // 		"Sig Data Len Error Code[%08X]", b.GM_MULTI_PACKLENTH_ERROR)
	// // }

	// if sigmtd == a1.SGD_SM3_RSA || sigmtd == a1.SGD_SM3_SM2 {
	// 	var sm3ctx C.SM3_CTX
	// C.sm3_resetctx(&sm3ctx, (*C.uchar)(unsafe.Pointer(&orgmindhash[0])))
	// C.sm3_update(&sm3ctx, (*C.uchar)(unsafe.Pointer(&sigdn[0])), (C.int)(sigdnl))
	// C.sm3_finish(&sm3ctx, (*C.uchar)(unsafe.Pointer(&midhash[0])))
	// } else {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataUpdate, b.GM_UNSUPPORT_SIGALT)
	// 	return b.CreateStdErr(b.GM_UNSUPPORT_SIGALT,
	// 		"Sig Data Unsupport SignAlg Code[%08X]", b.GM_UNSUPPORT_SIGALT)
	// }
	// rspb := a1.NewSVSRespondBuilder()
	// prtmsg, _ := rspb.BuildSignDataUpdateRespond(0, midhash[:])
	// rtmsg = prtmsg
	// conn.Write(rtmsg)
	return nil
}

// SignDataFinal 需厂家提供hash with ctx的接口
func sSignDataFinal(conn net.Conn, st *a1.Request_SignDataFinal_2) *b.StdErr {
	// var rtmsg []byte
	// sigmtd := st.SignMethod
	// keyidx := st.KeyIndex
	// keypin := st.KeyValue
	// fhash := st.HashVaule
	// var outsig [64]byte

	// sesh, iret := ISDF.OpenSession(CSDevH)
	// if iret != 0 {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataFinal, iret)
	// 	return b.CreateStdErr(iret,
	// 		"Sig Data SDF Func Error Code[%08X]", iret)
	// }
	// defer ISDF.CloseSession(sesh)

	// if sigmtd == a1.SGD_SM3_RSA || sigmtd == a1.SGD_SM3_SM2 {
	// 	iret = ISDF.GetPrivateKeyAccessRight(sesh, keyidx, keypin)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_SignDataFinal, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Sig Data SDF Func Error Code[%08X]", iret)
	// 	}
	// 	outsig1, iret := ISDF.ExternalSignECC(sesh,
	// 		ISDF.SGD_SM2_1, &CSSm2Map[keyidx].PrivKey, fhash)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_SignDataFinal, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Sig Data SDF Func Error Code[%08X]", iret)
	// 	}
	// 	copy(outsig[:32], outsig1.R[32:])
	// 	copy(outsig[32:64], outsig1.S[32:])
	// } else {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_SignDataFinal, b.GM_UNSUPPORT_SIGALT)
	// 	return b.CreateStdErr(iret,
	// 		"Sig Data SDF Func Error Code[%08X]", iret)
	// }

	// rspb := a1.NewSVSRespondBuilder()
	// prtmsg, _ := rspb.BuildSignDataFinalRespond(0, outsig[:])
	// rtmsg = prtmsg
	// conn.Write(rtmsg)
	return nil
}

// VerifySignedDataInit
func sVerifySignedDataInit(conn net.Conn, st *a1.Request_VerifySignedDataInit_2) *b.StdErr {
	// var rtmsg []byte
	// var outhash []byte
	// var iret int
	// sigmtd := st.SignMethod
	// pubk := st.SignerPublicKey
	// sid := st.SignerID
	// indata := st.InData
	// // indatal := st.InDataLen

	// // if indatal%C.SM3_BLOCK_SIZE != 0 {
	// // 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataInit, b.GM_MULTI_PACKLENTH_ERROR)
	// // 	return b.CreateStdErr(b.GM_MULTI_PACKLENTH_ERROR,
	// // 		"Verify Data Len Error Code[%08X]", b.GM_MULTI_PACKLENTH_ERROR)
	// // }

	// sesh, iret := ISDF.OpenSession(CSDevH)
	// if iret != 0 {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedData, iret)
	// 	return b.CreateStdErr(iret,
	// 		"Verify Data SDF Func Error Code[%08X]", iret)
	// }
	// defer ISDF.CloseSession(sesh)

	// if sigmtd == a1.SGD_SM3_RSA || sigmtd == a1.SGD_SM3_SM2 {
	// 	var ecpuk ISDF.ECCrefPublicKey
	// 	if pubk != nil {
	// 		ecpuk.Bits = 256
	// 		copy(ecpuk.X[32:], pubk[:32])
	// 		copy(ecpuk.Y[32:], pubk[32:64])
	// 		if sid == nil {
	// 			sid = []byte(b.SM2_DEFAULT_ID)
	// 		}
	// 		iret = ISDF.HashInit(sesh, ISDF.SGD_SM3, &ecpuk, sid)
	// 	} else {
	// 		iret = ISDF.HashInit(sesh, ISDF.SGD_SM3, nil, nil)
	// 	}
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataInit, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Verify Data SDF Func Error Code[%08X]", iret)
	// 	}

	// 	iret = ISDF.HashUpdate(sesh, indata)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataInit, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Verify Data SDF Func Error Code[%08X]", iret)
	// 	}

	// 	outhash, iret = ISDF.HashFinal(sesh)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataInit, iret)
	// 		return b.CreateStdErr(iret,
	// 			"Verify Data SDF Func Error Code[%08X]", iret)
	// 	}

	// } else {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataInit, b.GM_UNSUPPORT_SIGALT)
	// 	return b.CreateStdErr(iret,
	// 		"Sig Data SDF Func Error Code[%08X]", iret)
	// }

	// rspb := a1.NewSVSRespondBuilder()
	// prtmsg, _ := rspb.BuildVerifySignedDataInitRespond(0, outhash)
	// rtmsg = prtmsg
	// conn.Write(rtmsg)
	return nil
}

// VerifySignedDataUpdate
func sVerifySignedDataUpdate(conn net.Conn, st *a1.Request_VerifySignedDataUpdate_2) *b.StdErr {
	// var rtmsg []byte
	// sigmtd := st.SignMethod
	// orgmindhash := st.HashVaule
	// sigdn := st.InData
	// sigdnl := st.InDataLen
	// var midhash [32]byte

	// // if sigdnl%C.SM3_BLOCK_SIZE != 0 {
	// // 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataUpdate, b.GM_MULTI_PACKLENTH_ERROR)
	// // 	return b.CreateStdErr(b.GM_MULTI_PACKLENTH_ERROR,
	// // 		"Sig Data Len Error Code[%08X]", b.GM_MULTI_PACKLENTH_ERROR)
	// // }

	// if sigmtd == a1.SGD_SM3_RSA || sigmtd == a1.SGD_SM3_SM2 {
	// 	var sm3ctx C.SM3_CTX
	// 	C.sm3_resetctx(&sm3ctx, (*C.uchar)(unsafe.Pointer(&orgmindhash[0])))
	// 	C.sm3_update(&sm3ctx, (*C.uchar)(unsafe.Pointer(&sigdn[0])), (C.int)(sigdnl))
	// 	C.sm3_finish(&sm3ctx, (*C.uchar)(unsafe.Pointer(&midhash[0])))
	// } else {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataUpdate, b.GM_UNSUPPORT_SIGALT)
	// 	return b.CreateStdErr(b.GM_UNSUPPORT_SIGALT,
	// 		"Sig Data Unsupport SignAlg Code[%08X]", b.GM_UNSUPPORT_SIGALT)
	// }
	// rspb := a1.NewSVSRespondBuilder()
	// prtmsg, _ := rspb.BuildVerifySignedDataUpdateRespond(0, midhash[:])
	// rtmsg = prtmsg
	// conn.Write(rtmsg)
	return nil
}

// VerifySignedDataFinal
func sVerifySignedDataFinal(conn net.Conn, st *a1.Request_VerifySignedDataFinal_2) *b.StdErr {
	// var rtmsg []byte
	// hashv := st.HashValue
	// sesh, iret := ISDF.OpenSession(CSDevH)
	// if iret != 0 {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal, iret)
	// 	return b.CreateStdErr(iret,
	// 		"Verify Data SDF Func Error Code[%08X]", iret)
	// }
	// defer ISDF.CloseSession(sesh)

	// var caname []byte
	// if st.Type == 1 {
	// 	x509usercert, stderr := ISV.ParseCert2_x509(st.Cert.Bytes)
	// 	if stderr != nil {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal, b.GM_ERROR_CERT_DECODE)
	// 		return stderr
	// 	}

	// 	certidx1, caname1 := ISV.GetCertIdx_CAName_ByCertSerial(x509usercert.SerialNumber.Bytes())
	// 	if caname == nil || certidx1 == 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal, b.GM_ERROR_CERT)
	// 		return b.CreateStdErr(b.GM_ERROR_CERT,
	// 			"Verify Data No Match CA Cert Code[%08X]", b.GM_ERROR_CERT)
	// 	}
	// 	caname = caname1
	// } else {
	// 	certidx1, caname1 := ISV.GetCertIdx_CAName_ByCertSerial(st.CertSN.Bytes)
	// 	if caname == nil || certidx1 == 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal, b.GM_ERROR_CERT)
	// 		return b.CreateStdErr(b.GM_ERROR_CERT,
	// 			"Verify Data No Match CA Cert Code[%08X]", b.GM_ERROR_CERT)
	// 	}
	// 	caname = caname1
	// }

	// if st.Type == 1 {
	// 	stderr := ISV.VerifyCert(sesh, caname, st.Cert.Bytes, nil, st.VerifyLevel)
	// 	if stderr != nil {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal, stderr.Errcode)
	// 		return b.CreateStdErr(stderr.Errcode,
	// 			"Verify Data Error Code[%08X]", stderr.Errcode)
	// 	}
	// } else {
	// 	cacertinfo, _, _, stderr := ISV.ParseTBSFromDER(ISV.GCaInfo[string(caname)].CertPem)
	// 	if stderr != nil {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal, stderr.Errcode)
	// 		return stderr
	// 	}

	// 	bsig, err := a1.Decode_asn1RawSM2Sig_2_bSM2Sig(st.Signature)
	// 	if err != nil {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal,
	// 			b.GM_UNSUPPORT_SIGNATURE_VALUE)
	// 		return b.CreateStdErr(b.GM_UNSUPPORT_SIGNATURE_VALUE,
	// 			"Verify Data Unknow SigData[%08X]", b.GM_UNSUPPORT_SIGNATURE_VALUE)
	// 	}
	// 	var sig ISDF.ECCSignature
	// 	copy(sig.R[32:], bsig[:32])
	// 	copy(sig.S[32:], bsig[32:64])
	// 	iret = ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2_1, &cacertinfo.PublicKey, hashv, &sig)
	// 	if iret != 0 {
	// 		sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedDataFinal,
	// 			iret)
	// 		return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	// 	}
	// }

	// rspb := a1.NewSVSRespondBuilder()
	// prtmsg, _ := rspb.BuildVerifySignedDataFinalRespond(0)
	// rtmsg = prtmsg
	// conn.Write(rtmsg)
	return nil
}

// SignMessage
func sSignMessage(conn net.Conn, st *a1.Request_SignMessage_2) *b.StdErr {
	var rtmsg []byte
	signmthd := st.SignMethod
	keyidx := st.KeyIndex*2 - 1
	keypin := st.KeyValue
	indata := st.InData
	// indatalen := st.InDataLen

	hashflag := st.HashFlag
	orgtest := st.OriginalText
	certchain := st.CertificateChain
	crl := st.Crl
	authatt := st.AuthenticationAttributes

	var oid []int
	if signmthd == a1.SGD_SM3_SM2 {
		oid = []int{1, 2, 156, 10197, 1, 501}
	} else if signmthd == a1.SGD_SM3_RSA {
		oid = []int{1, 2, 156, 10197, 1, 504}
	}

	sesh, iret := ISDF.OpenSession(CSDevH)
	if iret != 0 {
		sendErrorMsgBackSV(conn, a1.ReqType_SignMessage,
			iret)
		return base.CreateStdErr(iret, "Sign Message Error Code [%08X]", iret)
	}
	defer ISDF.CloseSession(sesh)

	var outhash []byte
	if hashflag == false {
		if signmthd == a1.SGD_SM3_RSA || signmthd == a1.SGD_SM3_SM2 {
			outhash1, iret := ISDF.Hash(sesh, indata)
			if iret != 0 {
				sendErrorMsgBackSV(conn, a1.ReqType_SignMessage,
					iret)
				return base.CreateStdErr(iret, "Sign Message Error Code [%08X]", iret)
			}
			outhash = outhash1
		} else {
			sendErrorMsgBackSV(conn, a1.ReqType_SignMessage, b.GM_UNSUPPORT_SIGALT)
			return b.CreateStdErr(iret,
				"Sig Message SDF Func Error Code[%08X]", iret)
		}
	} else {
		outhash = indata
	}

	// get access right
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		sendErrorMsgBackSV(conn, a1.ReqType_SignMessage, b.SDR_KEYNOTEXIST)
		return b.CreateStdErr(int(b.SDR_KEYNOTEXIST),
			"Sig Message SDF Func Error ret : %08X", b.SDR_KEYNOTEXIST)
	}
	if CSSm2Map[int(keyidx)].PrivKeyAuth == 0 {
	} else {
		pwddig, iret := ISDF.Hash(sesh, keypin)
		if iret != 0 {
			sendErrorMsgBackSV(conn, a1.ReqType_SignMessage, iret)
			return b.CreateStdErr(iret,
				"Sig Message SDF Func Error Code[%08X]", iret)
		}

		pivpin := CSSm2Map[int(keyidx)].PrivPin
		if bytes.Equal(pwddig, pivpin[:]) {
			RWmu.Lock()
			SM2KeyCanUseList[conn][keyidx] = 1
			SM2KeyCanUseList[conn][keyidx+1] = 1
			RWmu.Unlock()
		} else {
			sendErrorMsgBackSV(conn, a1.ReqType_SignMessage, b.SDR_PARDENY)
			return b.CreateStdErr(b.SDR_PARDENY,
				"Sig Message SDF Func Error Code[%08X]", b.SDR_PARDENY)
		}
	}
	defer func() {
		SM2KeyCanUseList[conn] = nil
	}()

	var sig [64]byte
	outsig, iret := ISDF.ExternalSignECC(sesh,
		ISDF.SGD_SM2_1, &CSSm2Map[keyidx].PrivKey, outhash)
	if iret != 0 {
		sendErrorMsgBackSV(conn, a1.ReqType_SignMessage,
			iret)
		return base.CreateStdErr(iret, "Sign Message Error Code [%08X]", iret)
	}
	copy(sig[:32], outsig.R[32:])
	copy(sig[32:64], outsig.S[32:])

	var sm2sig a1.SM2Signature
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	sm2sig.R = r
	sm2sig.S = s

	sd := a1.SignedData{
		Version:          1,
		DigestAlgorithms: oid,
		ContentInfo:      sm2sig,
	}

	sn := ISV.GetAppCertSerialByKeyIdx(2, keyidx, 0)
	if sn == nil {
		sendErrorMsgBackSV(conn, a1.ReqType_SignMessage,
			b.GM_ERROR_CERT)
		return base.CreateStdErr(b.GM_ERROR_CERT,
			"Sign Message Error Code [%08X]", b.GM_ERROR_CERT)
	}

	sif := a1.SignerInfo{
		Version:                   1,
		IssuerAndSerialNumber:     ISV.GAppCertInfo[string(sn)].CertSerial,
		DigestAlgorithm:           asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}, // SM3 OID
		AuthenticatedAttributes:   nil,
		DigestEncryptionAlgorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}, // SM2 OID
		EncryptedDigest:           sm2sig,
	}

	if certchain {
		sd.Certificates = append(sd.Certificates, ISV.GAppCertInfo[string(sn)].CertPem...)
	}

	if orgtest {
		sif.AuthenticatedAttributes = append(sif.AuthenticatedAttributes, indata...)
	}

	if crl {
		sd.CRLs = append(sd.CRLs,
			[]byte(ISV.GAppCertInfo[string(sn)].X509Cert.CRLDistributionPoints[0])...)
	}

	if authatt {

	}

	sd.SignerInfos = append(sd.SignerInfos, sif)
	signedmsg, _ := a1.Marshal(sd)
	rspb := a1.NewSVSRespondBuilder()
	prtmsg, _ := rspb.BuildSignMessageRespond(0, signedmsg)

	rtmsg = prtmsg
	conn.Write(rtmsg)
	return nil
}

// VerifySignedMessage
func sVerifySignedMessage(conn net.Conn, st *a1.Request_VerifySignedMessage_2) *b.StdErr {
	// var rtmsg []byte
	// indata := st.InData
	// signedmsg := st.SignedMessage

	// hashflag := st.HashFlag
	// orgtest := st.OriginalText
	// certchain := st.CertificateChain
	// crl := st.Crl
	// authatt := st.AuthenticationAttributes

	// var sd a1.SignedData
	// _, err := a1.UnMarshal(signedmsg, &sd)
	// if err != nil {
	// 	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedMessage,
	// 		b.GM_INVALID_DATA_FORMAT)
	// 	return base.CreateStdErr(b.GM_INVALID_DATA_FORMAT,
	// 		"Verify Sign Message Error Code [%08X]", b.GM_INVALID_DATA_FORMAT)
	// }

	// var sig ISDF.ECCSignature
	// copy(sig.R[32:], bsig[:32])
	// copy(sig.S[32:], bsig[32:64])
	// iret = ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2_1, &appcertinfo.PublicKey, outhash, &sig)
	// if iret != 0 {
	// 	return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	// }

	return nil
}

// SignMessageInit
func sSignMessageInit(conn net.Conn, st *a1.Request_SignMessageInit_2) *b.StdErr {
	sendErrorMsgBackSV(conn, a1.ReqType_SignMessageInit, b.GM_MULTI_OPERATION_ERROR)
	return nil
}

// SignMessageUpdate
func sSignMessageUpdate(conn net.Conn, st *a1.Request_SignMessageUpdate_2) *b.StdErr {
	sendErrorMsgBackSV(conn, a1.ReqType_SignMessageUpdate, b.GM_MULTI_OPERATION_ERROR)
	return nil
}

// SignMessageFinal
func sSignMessageFinal(conn net.Conn, st *a1.Request_SignMessageFinal_2) *b.StdErr {
	sendErrorMsgBackSV(conn, a1.ReqType_SignMessageFinal, b.GM_MULTI_OPERATION_ERROR)
	return nil
}

// VerifySignedMessageInit
func sVerifySignedMessageInit(conn net.Conn, st *a1.Request_VerifySignedMessageInit_2) *b.StdErr {
	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedMessageInit, b.GM_MULTI_OPERATION_ERROR)
	return nil
}

// VerifySignedMessageUpdate
func sVerifySignedMessageUpdate(conn net.Conn, st *a1.Request_VerifySignedMessageUpdate_2) *b.StdErr {
	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedMessageUpdate, b.GM_MULTI_OPERATION_ERROR)
	return nil
}

// VerifySignedMessageFinal
func sVerifySignedMessageFinal(conn net.Conn, st *a1.Request_VerifySignedMessageFinal_2) *b.StdErr {
	sendErrorMsgBackSV(conn, a1.ReqType_VerifySignedMessageFinal, b.GM_MULTI_OPERATION_ERROR)
	return nil
}
