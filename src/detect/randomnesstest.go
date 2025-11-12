package detect

/*
#cgo LDFLAGS: -L ./nist_sts-master/build/nist_sts -lnist_sts -lm
#include "./nist_sts-master/nist_sts/include/stat_fncs.h"
*/
import "C"
import (
	"fmt"
	"io"
	"os"
	b "sig_vfy/src/base"
	"sync"
	"unsafe"
)

func bytesToBitSeq(inbytes []byte) []byte {
	var outbitseq []byte = make([]byte, len(inbytes)*8)
	fmt.Printf("Bytes Converting Please Wait...\n")
	C.BytesToBitSequence(
		(*C.uchar)(unsafe.Pointer(&inbytes[0])), C.int(len(inbytes)),
		(*C.uchar)(unsafe.Pointer(&outbitseq[0])), C.int(len(outbitseq)))
	fmt.Printf("Bytes Converting Complete\n")

	return outbitseq
}

func bytesFromFileToBitSeq(filepath string, readLen int) ([]byte, *b.StdErr) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil,
			b.CreateStdErr(b.OPENFILE_ERROR,
				"Open Random File Error")
	}

	fmt.Printf("Reading Files Please wait...\n")
	readbytes := make([]byte, readLen)
	_, err = io.ReadFull(file, readbytes)
	if err != nil {
		return nil,
			b.CreateStdErr(b.READFILE_ERROR,
				"Read Random File Error")
	}
	defer file.Close()
	fmt.Printf("Reading Complete\n")
	fmt.Println("Read Len = ", len(readbytes))

	return bytesToBitSeq(readbytes), nil
}

/**
 * 1.单比特频数检测
 * @param n
 * @return
 */
func frequency(n int, bseqence []byte) int {
	ret := C.Frequency(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 2.块内频数检测
 * @param M
 * @param n
 * @return
 */
func blockFrequency(m int, n int, bseqence []byte) int {
	ret := C.BlockFrequency(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 3.累加和检测
 * @param n
 * @return
 */
func cumulativeSums(n int, bseqence []byte) int {
	ret := C.CumulativeSums(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 4.游程总数检测
 * @param n
 * @return
 */
func runs(n int, bseqence []byte) int {
	ret := C.Runs(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 5.块内最大“1”游程检测
 * @param n
 * @return
 */
func longestRunOfOnes(n int, bseqence []byte) int {
	ret := C.LongestRunOfOnes(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 6.矩阵秩检测
 * @param n
 * @return
 */
func rank(n int, bseqence []byte) int {
	ret := C.Rank(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 7.离散傅立叶检测
 * @param n
 * @return
 */
func discreteFourierTransform(n int, bseqence []byte) int {
	ret := C.DiscreteFourierTransform(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 8.非重叠模版匹配测试
 * @param m
 * @param n
 * @return
 */
func nonOverlappingTemplateMatchings(m int, n int, bseqence []byte) int {
	ret := C.NonOverlappingTemplateMatchings(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 9.重叠模版匹配测试
 * @param m
 * @param n
 * @return
 */
func overlappingTemplateMatchings(m int, n int, bseqence []byte) int {
	ret := C.OverlappingTemplateMatchings(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 10.通用统计检测
 * @param n
 * @return
 */
func universal(n int, bseqence []byte) int {
	ret := C.Universal(C.int(n), (*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 11.近似熵检测
 * @param m
 * @param n
 * @return
 */
func approximateEntropy(m int, n int, bseqence []byte) int {
	ret := C.ApproximateEntropy(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 12.自由游程测试
 * @param n
 * @return
 */
func randomExcursions(n int, bseqence []byte) int {
	ret := C.RandomExcursions(C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 13.自由变量测试
 * @param n
 * @return
 */
func randomExcursionsVariant(n int, bseqence []byte) int {
	ret := C.RandomExcursionsVariant(C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 14.线性复杂度检测
 * @param M
 * @param n
 * @return
 */
func linearComplexity(m int, n int, bseqence []byte) int {
	ret := C.LinearComplexity(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 15.重叠子序列检测
 * @param m
 * @param n
 * @return
 */
func serial(m int, n int, bseqence []byte) int {
	ret := C.Serial(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 16.二元推导检测
 * @param k
 * @param n
 * @param epsilon
 * @return
 */
func binaryDerivate(k int, n int, bseqence []byte, epsilon_l int) int {
	ret := C.BinaryDerivate(C.int(k), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])), C.int(epsilon_l))
	return int(ret)
}

/**
 * 17.自相关测试
 * @param d
 * @param n
 * @param epsilon
 * @return
 */
func selfCorrelation(d int, n int, bseqence []byte) int {
	ret := C.SelfCorrelation(C.int(d), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 18.扑克检测
 * @param M
 * @param n
 * @param epsilon
 * @return
 */
func pokerDetect(m int, n int, bseqence []byte) int {
	ret := C.PokerDetect(C.int(m), C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

/**
 * 19.游程分布检测
 * @param n
 * @param epsilon
 * @return
 */
func runsDistribution(n int, bseqence []byte) int {
	ret := C.RunsDistribution(C.int(n),
		(*C.uchar)(unsafe.Pointer(&bseqence[0])))
	return int(ret)
}

// ------------------------------------------------------------------------------------
var podList = map[int]string{
	0:  "Frequency",
	1:  "BlockFrequency",
	2:  "PokerDetect",
	3:  "Serial",
	4:  "Runs",
	5:  "RunsDistribution",
	6:  "LongestRunOfOnes",
	7:  "BinaryDerivate",
	8:  "SelfCorrelation",
	9:  "Rank",
	10: "CumulativeSums",
	11: "ApproximateEntropy",
	12: "LinearComplexity",
	13: "Universal",
	14: "DiscreteFourierTransform",
}

var cycList = map[int]string{
	0:  "Frequency",
	1:  "BlockFrequency",
	2:  "PokerDetect",
	3:  "Serial",
	4:  "Runs",
	5:  "RunsDistribution",
	6:  "LongestRunOfOnes",
	7:  "BinaryDerivate",
	8:  "SelfCorrelation",
	9:  "Rank",
	10: "CumulativeSums",
	11: "ApproximateEntropy",
}

func pthPowerOnDetection(bitseq []byte) [15]int {
	var passnums [15]int
	passnums[0] += frequency(10000, bitseq)
	passnums[1] += blockFrequency(100, 10000, bitseq)
	passnums[2] += pokerDetect(8, 10000, bitseq)
	passnums[3] += serial(2, 10000, bitseq)
	passnums[4] += runs(1000000, bitseq)
	passnums[5] += runsDistribution(10000, bitseq)
	passnums[6] += longestRunOfOnes(10000, bitseq)
	passnums[7] += binaryDerivate(3, 10000, bitseq, 8)
	passnums[8] += selfCorrelation(8, 10000, bitseq)
	passnums[9] += rank(10000, bitseq)
	passnums[10] += cumulativeSums(10000, bitseq)
	passnums[11] += approximateEntropy(5, 10000, bitseq)
	passnums[12] += linearComplexity(500, 1000000, bitseq)
	passnums[13] += universal(1000000, bitseq)
	passnums[14] += discreteFourierTransform(10000, bitseq)
	return passnums
}

func pthCycleDetection(bitseq []byte) [12]int {
	var passnums [12]int
	passnums[0] += frequency(10000, bitseq)
	passnums[1] += blockFrequency(100, 10000, bitseq)
	passnums[2] += pokerDetect(8, 10000, bitseq)
	passnums[3] += serial(2, 10000, bitseq)
	passnums[4] += runs(b.CYC_PERBITLEN, bitseq)
	passnums[5] += runsDistribution(10000, bitseq)
	passnums[6] += longestRunOfOnes(10000, bitseq)
	passnums[7] += binaryDerivate(3, 10000, bitseq, 8)
	passnums[8] += selfCorrelation(8, 10000, bitseq)
	passnums[9] += rank(10000, bitseq)
	passnums[10] += cumulativeSums(10000, bitseq)
	passnums[11] += approximateEntropy(5, 10000, bitseq)
	return passnums
}

// 上电检测
func PowerOnDetection(filepath string) ([15]int, *b.StdErr) {
	var passnums [15]int
	var bitseqLen = b.POD_CYCLE * b.POD_PERBITLEN / 8
	bitseq, err := bytesFromFileToBitSeq(filepath, bitseqLen)
	if err != nil {
		return passnums, err
	}

	if len(bitseq) < (bitseqLen) {
		return passnums,
			b.CreateStdErr(b.POWERONDET_RANDLEN_ERROR,
				"PowerOnDetection RandomFile Len Error ReadLen = %d Standard Len Should = %d",
				len(bitseq), (bitseqLen))
	}

	resultChan := make(chan [15]int)
	var wg sync.WaitGroup

	fmt.Printf("PowerOn Detection Running...\n")
	for i := 0; i < b.POD_CYCLE; i++ {
		left := i * b.POD_PERBITLEN
		right := (i + 1) * b.POD_PERBITLEN
		wg.Add(1)
		go func() {
			defer wg.Done()
			pthpassnums := pthPowerOnDetection(bitseq[left:right])
			resultChan <- pthpassnums
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
		fmt.Printf("PowerOn Detection Complete\n")
	}()

	for pthpassnums := range resultChan {
		for i := 0; i < len(passnums); i++ {
			passnums[i] += pthpassnums[i]
		}
	}

	for i := 0; i < int(len(passnums)); i++ {
		if float32(passnums[i]) < float32(
			float32(b.POD_CYCLE)*b.POD_PASSRATE) {
			var elist string
			for j := 0; j < int(len(passnums)); j++ {
				elist +=
					fmt.Sprintf("%-2d. %-25s passtimes : %d\n",
						j+1, podList[j], passnums[j])
			}
			return passnums,
				b.CreateStdErr(b.POWERONDET_RANDRES_ERROR, elist)
		}
	}
	return passnums, nil
}

// 周期检测
func CycleDetection(filepath string) ([12]int, *b.StdErr) {
	var passnums [12]int
	var bitseqLen = b.POD_CYCLE * b.CYC_PERBITLEN / 8
	bitseq, err := bytesFromFileToBitSeq(filepath, bitseqLen)
	if err != nil {
		return passnums, err
	}

	if len(bitseq) < (bitseqLen) {
		return passnums,
			b.CreateStdErr(b.CYCDET_RANDLEN_ERROR,
				"CycleDetection RandomFile Len Error ReadLen = %d Standard Len Should = %d",
				len(bitseq), (bitseqLen))
	}

	resultChan := make(chan [12]int)
	var wg sync.WaitGroup

	fmt.Printf("CycleDetection Running...\n")
	for i := 0; i < b.CYC_CYCLE; i++ {
		left := i * b.CYC_PERBITLEN
		right := (i + 1) * b.CYC_PERBITLEN
		wg.Add(1)
		go func() {
			defer wg.Done()
			pthpassnums := pthCycleDetection(bitseq[left:right])
			resultChan <- pthpassnums
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
		fmt.Printf("CycleDetection Complete\n")
	}()

	for pthpassnums := range resultChan {
		for i := 0; i < len(passnums); i++ {
			passnums[i] += pthpassnums[i]
		}
	}

	for i := 0; i < int(len(passnums)); i++ {
		if float32(passnums[i]) < float32(
			float32(b.CYC_CYCLE)*b.CYC_PASSRATE) {
			var elist string
			for j := 0; j < int(len(passnums)); j++ {
				elist +=
					fmt.Sprintf("%-2d. %-25s passtimes : %d\n",
						j+1, podList[j], passnums[j])
			}
			return passnums,
				b.CreateStdErr(b.CYCDET_RANDRES_ERROR, elist)
		}
	}
	return passnums, nil
}
