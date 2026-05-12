package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	targetFile    = "final_urls.txt"
	interfaceName = "eno1"
	snapLen       = 65535
)

func main() {
	// 1. 실패 로그 파일 오픈 (Append 모드)
	failFile, err := os.OpenFile("failed_urls.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("[오류] 실패 로그 파일을 생성할 수 없습니다: %v\n", err)
	}
	defer failFile.Close()

	// 2. 대상 파일 읽기 및 슬라이스 저장
	file, err := os.Open(targetFile)
	if err != nil {
		log.Fatalf("[오류] %s 파일을 열 수 없습니다: %v\n", targetFile, err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	// 3. 리스트 셔플 (동일 도메인 연속 요청 방지)
	fmt.Printf("[정보] 총 %d개의 URL을 로드했습니다. 순서를 섞는 중...\n", len(urls))
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(urls), func(i, j int) {
		urls[i], urls[j] = urls[j], urls[i]
	})

	// 4. 병렬 처리를 위한 채널 및 WaitGroup 설정
	urlChan := make(chan string)
	var wg sync.WaitGroup

	// 작업자 수 설정 (24스레드 환경이므로 20~30개 추천)
	// 너무 높으면 네트워크 인터페이스 부하가 생길 수 있음
	workerCount := 15

	fmt.Printf("[정보] %d개의 워커로 수집을 시작합니다.\n", workerCount)

	// 5. Worker 실행
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for url := range urlChan {
				processTarget(url, failFile)
			}
		}(i)
	}

	// 6. 셔플된 URL을 채널에 투입
	for _, url := range urls {
		urlChan <- url
	}

	// 7. 종료 처리
	close(urlChan)
	wg.Wait()

	fmt.Println("[완료] 모든 대상의 병렬 트래픽 캡처가 종료되었습니다.")
}

func processTarget(rawURL string, failFile *os.File) {
	// 실패 기록을 위한 헬퍼 함수
	logFailure := func(reason string, err error) {
		errorMessage := fmt.Sprintf("[실패] %s (%s): %v", rawURL, reason, err)
		log.Println(errorMessage)
		// failed_urls.txt에 URL 기록
		if failFile != nil {
			failFile.WriteString(fmt.Sprintf("%s\n", rawURL))
		}
	}

	// 1. URL 정리 및 파싱
	urlStr := rawURL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://" + urlStr
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		logFailure("URL 파싱 불가", err)
		return
	}

	domain := u.Hostname()
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	fmt.Printf("[시작] 대상: %s (SNI: %s, Path: %s)\n", rawURL, domain, path)

	// 2. DNS 조회 (도메인만 사용)
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		logFailure("IP 해석 불가", err)
		return
	}
	targetIP := ips[0].String()

	// 3. PCAP 핸들 오픈
	handle, err := pcap.OpenLive(interfaceName, snapLen, true, 100*time.Millisecond)
	if err != nil {
		logFailure("인터페이스 열기 실패", err)
		return
	}
	defer handle.Close()

	// BPF 필터 설정
	filter := fmt.Sprintf("host %s and port 443", targetIP)
	if err := handle.SetBPFFilter(filter); err != nil {
		logFailure("BPF 필터 설정 실패", err)
		return
	}

	// 4. 폴더 및 파일 경로 설정 (SNI별 정리)
	outputBase := "output"
	domainDir := filepath.Join(outputBase, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		logFailure("폴더 생성 실패", err)
		return
	}

	// 파일명 안전하게 생성 (슬래시 제거)
	safePath := strings.ReplaceAll(path, "/", "_")
	if safePath == "_" || safePath == "" {
		safePath = "root"
	}
	pcapFilename := filepath.Join(domainDir, fmt.Sprintf("%s_%d.pcap", safePath, time.Now().Unix()))

	pcapFile, err := os.Create(pcapFilename)
	if err != nil {
		logFailure("PCAP 파일 생성 실패", err)
		return
	}
	defer pcapFile.Close()

	pcapWriter := pcapgo.NewWriter(pcapFile)
	pcapWriter.WriteFileHeader(uint32(snapLen), layers.LinkTypeEthernet)

	// 5. 패킷 캡처 고루틴 설정
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, ci, err := handle.ReadPacketData()
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				if err != nil {
					return
				}
				pcapWriter.WritePacket(ci, data)
			}
		}
	}()

	fmt.Println("[정보] 트래픽 캡처 시작...")

	// 6. TCP 연결 및 uTLS 핸드셰이크
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, "443"), 5*time.Second)
	if err != nil {
		logFailure("TCP 연결 실패", err)
		cancel()
		wg.Wait()
		return
	}

	// utls.HelloChrome_Auto : Chrome 최신 설정
	// utls.HelloCustom : 커스텀 설정
	uConn := utls.UClient(conn, &utls.Config{ServerName: domain}, utls.HelloChrome_Auto)

	// TLS Spec 설정, ApplyPreset까지.
	// spec := utls.ClientHelloSpec{
	// 	TLSVersMin: utls.VersionTLS13,
	// 	TLSVersMax: utls.VersionTLS13,
	// 	CipherSuites: []uint16{
	// 		utls.TLS_AES_128_GCM_SHA256,
	// 		utls.TLS_CHACHA20_POLY1305_SHA256,
	// 		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	// 		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	// 	},
	// 	Extensions: []utls.TLSExtension{
	// 		&utls.SNIExtension{},
	// 		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
	// 		&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
	// 		&utls.SessionTicketExtension{},
	// 		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
	// 			utls.ECDSAWithP256AndSHA256,
	// 			utls.PSSWithSHA256,
	// 			utls.PKCS1WithSHA256,
	// 		}},
	// 		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
	// 			{Group: utls.CurveID(utls.X25519)},
	// 		}},
	// 		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
	// 		&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
	// 	},
	// }

	// if err := uConn.ApplyPreset(&spec); err != nil {
	// 	logFailure("uTLS 설정 실패", err)
	//} else {

	if err := uConn.Handshake(); err != nil {
		logFailure("TLS 핸드셰이크 실패", err)
	} else {
		negotiated := uConn.ConnectionState().NegotiatedProtocol
		fmt.Printf("[정보] TLS 핸드셰이크 성공 (Negotiated Protocol: %s)\n", negotiated)

		var tr http.RoundTripper

		if negotiated == "h2" {
			tr = &http2.Transport{
				DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
					return uConn, nil
				},
			}
		} else {
			tr = &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return uConn, nil
				},
			}
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}

		req, err := http.NewRequest("GET", "https://"+domain, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[실패] HTTP 요청 실패: %v\n", err)
				logFailure("HTTP 요청 실패", err)
			} else {
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				fmt.Printf("[정보] 서버 응답 수신 완료 (상태 코드: %d)\n", resp.StatusCode)
			}
		}
	}

	uConn.Close()
	conn.Close()

	// 패킷 누락 방지를 위한 대기
	fmt.Println("[정보] 종료 대기 중 (2초)...")
	time.Sleep(2 * time.Second)

	cancel()
	wg.Wait()
	fmt.Printf("[성공] %s 저장 완료\n\n", pcapFilename)
}
