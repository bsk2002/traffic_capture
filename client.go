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

// ============================================================
//  설정
// ============================================================

const (
	targetFile    = "urls.txt"	// 접근하고자 하는 url 목록
	interfaceName = "en0"		// 네트워크 인터페이스 (linux: eno1, mac: en0)
	workerCount   = 1			// 병렬 처리할 worker 개수
	outputBase    = "output"	// 결과를 저장할 폴더명

	// 사용할 브라우저 핑거프린트 지정
	// chrome, firefox, safari, ios, edge, 360, qq, custom
	helloType = "chrome"
)

// ============================================================
//  커스텀 ClientHello 정의 
// ============================================================

func buildCustomSpec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SessionTicketExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
		},
	}
}

// ============================================================

func main() {
	failFile, err := os.OpenFile("failed_urls.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("[오류] 실패 로그 파일 생성 불가: %v\n", err)
	}
	defer failFile.Close()

	file, err := os.Open(targetFile)
	if err != nil {
		log.Fatalf("[오류] %s 열기 실패: %v\n", targetFile, err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			urls = append(urls, line)
		}
	}

	fmt.Printf("[정보] %d개 URL 로드. 셔플 중...\n", len(urls))
	r := rand.New(rand.NewSource(42))
	r.Shuffle(len(urls), func(i, j int) { urls[i], urls[j] = urls[j], urls[i] })

	urlChan := make(chan string, workerCount)
	var wg sync.WaitGroup

	// workerCount만큼 goroutine 생성
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urlChan {
				processTarget(u, failFile)
			}
		}()
	}

	for _, u := range urls {
		urlChan <- u
	}
	close(urlChan) // urlChan(채널)에 url을 모두 올렸다면 채널을 닫음
	wg.Wait() // 작업 중인 고루틴이 모두 종료되기를 기다림

	fmt.Println("[완료] 모든 캡처 작업 종료.")
}

func processTarget(rawURL string, failFile *os.File) {
	logFailure := func(reason string, err error) {
		log.Printf("[실패] %s (%s): %v\n", rawURL, reason, err)
		if failFile != nil {
			failFile.WriteString(rawURL + "\n")
		}
	}

	// 1. URL 파싱
	urlStr := rawURL
	if !strings.HasPrefix(urlStr, "http") { // http로 시작하지 않으면 'https://'를 붙임
		urlStr = "https://" + urlStr
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		logFailure("URL 파싱 실패", err)
		return
	}
	domain := u.Hostname() // 도메인 이름만 추출
	fmt.Printf("[시작] %s\n", domain)

	// 2. DNS 조회
	ips, err := net.LookupIP(domain) // 도메인을 기반으로 DNS 서버에 질의, 연결된 IP 목록 반환
	if err != nil || len(ips) == 0 {
		logFailure("DNS 조회 실패", err)
		return
	}
	targetIP := ips[0].String()

	// 3. pcap 핸들 오픈 (TCP 연결 전 → 3-way handshake 포함)
	handle, err := pcap.OpenLive(interfaceName, 65535, false, 100*time.Millisecond) // handle 객체 생성
	if err != nil {
		logFailure("인터페이스 오픈 실패", err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("host %s and port 443", targetIP)); err != nil { // BPF 필터 조건 설정 (targetIP, https 기록만 캡처)
		logFailure("BPF 필터 설정 실패", err)
		return
	}

	// 4. 출력 경로
	ts := time.Now().UnixNano()
	domainDir := filepath.Join(outputBase, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		logFailure("디렉토리 생성 실패", err)
		return
	}
	pcapPath := filepath.Join(domainDir, fmt.Sprintf("%d.pcap", ts))

	pcapFile, err := os.Create(pcapPath)
	if err != nil {
		logFailure("pcap 파일 생성 실패", err)
		return
	}
	defer pcapFile.Close()

	// 4-1. keylog 파일 생성 (복호화를 위함)
	keylogPath := filepath.Join(domainDir, fmt.Sprintf("%d.keylog", ts))
	keylogFile, err := os.Create(keylogPath)
	if err != nil {
		logFailure("keylog 파일 생성 실패", err)
		return
	}
	defer keylogFile.Close()

	pcapWriter := pcapgo.NewWriter(pcapFile) // pcap 형식으로 데이터를 쓸 수 있는 writer
	pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet) // pcap 파일의 헤더를 작성

	// 5. 캡처 고루틴 시작 (TCP 연결 전)
	ctx, cancel := context.WithCancel(context.Background())
	var captureWg sync.WaitGroup
	captureWg.Add(1)
	go func() {
		defer captureWg.Done()
		for { // 무한루프
			select {
			case <-ctx.Done(): // ctx의 채널이 닫혀있으면 return
				return
			default:
				data, ci, err := handle.ReadPacketData() // NIC에서 packet 1개를 꺼냄 (raw data, CaptureInfo, error)
				if err == pcap.NextErrorTimeoutExpired { // handle 객체의 timeout을 감지한다면 다시 for문 무한루프
					continue
				}
				if err != nil {
					return
				}
				pcapWriter.WritePacket(ci, data) // pcap 파일에 기록
			}
		}
	}()

	// 6. TCP 연결
	// net.JoinHostPort(targetIP, "443") => "192[.]168[.]0[.]1:443" 형태로 결합.
	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, "443"), 5*time.Second) // TCP 연결 시도. NIC에서 SYN 패킷을 전송하는 역할. 
	if err != nil {
		logFailure("TCP 연결 실패", err)
		cancel()
		captureWg.Wait() // captureWg.Done()을 기다림
		return
	}

	// 7. uTLS 브라우저 변조 (ClientHello fingerprint)
	var uConn *utls.UConn
	var helloIDMap = map[string]utls.ClientHelloID{
		"chrome": utls.HelloChrome_Auto,
		"firefox": utls.HelloFirefox_Auto,
		"safari": utls.HelloSafari_Auto,
		"ios": utls.HelloIOS_Auto,
		"edge":utls.HelloEdge_Auto,
		"360": utls.Hello360_Auto,
		"qq": utls.HelloQQ_Auto,

		"custom": utls.HelloCustom,
	}
	helloID, exists := helloIDMap[helloType]
	if !exists {
		helloID = utls.HelloChrome_Auto
		fmt.Println("[경고] 기본값으로 HelloChrome_Auto 사용")
	}

	uConn = utls.UClient(tcpConn, &utls.Config{
        ServerName:   domain,
        KeyLogWriter: keylogFile,
    }, helloID)

	if helloType == "custom" {
		spec := buildCustomSpec()
		
		if err := uConn.ApplyPreset(&spec); err != nil {
			logFailure("커스텀 ClientHello 적용 실패", err)
			tcpConn.Close()
			cancel()
			captureWg.Wait()
			return
		}
		fmt.Println("[정보] CustomHello 사용")
	}

	// 8. TLS handshake
	// 이 과정에서 keylog 파일 write 진행 (수행 객체: KeyLogWriter)
	if err := uConn.Handshake(); err != nil { // uConn으로 handshake 시도. NIC에서 ClientHello를 서버로 전송.
		logFailure("TLS 핸드셰이크 실패", err)
		uConn.Close()
		cancel()
		captureWg.Wait()
		return
	}
	negotiated := uConn.ConnectionState().NegotiatedProtocol // 협상된 ALPN 확인
	fmt.Printf("[정보] 핸드셰이크 성공 (protocol: %s)\n", negotiated)

	// 9. HTTP 요청
	var tr http.RoundTripper // req를 받아서 소켓 열기, 암호화, byte 단위로 쪼개서 서버로 전송, response 객체로 받기 등을 수행

	// http/1.1과 h2에 따라 golang에서 사용하는 signature가 다름 (DialTLS, DialTLSContext)
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

	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://"+domain+"/", nil) // 첫 번쨰 화면의 HTML 소스 코드를 받아옴
	if err != nil {
		logFailure("HTTP 요청 생성 실패", err)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36") // 브라우저에 따라 바꾸는 것이 좋음
		req.Header.Set("Connection", "close") // FIN 유도
		resp, err := client.Do(req) // NIC에서 서버로 데이터를 보내는 시점
		if err != nil {
			logFailure("HTTP 요청 실패", err)
		} else {
			io.Copy(io.Discard, resp.Body) // FIN을 정확하게 캡처하기 위해 resp.Body를 모두 소비하여 버퍼를 비움 -> uConn.Close()에서 버퍼가 비어있어야 정확히 FIN을 보냄
			resp.Body.Close()
			fmt.Printf("[정보] HTTP 응답 수신 (status: %d)\n", resp.StatusCode)
		}
	}

	// 10. 연결 종료 (FIN) → 대기 후 캡처 종료
	uConn.Close() // FIN 전송 시점
	time.Sleep(2 * time.Second) // FIN-ACK 수신 대기

	cancel() // 캡처 고루틴 종료 (5번 단계에서 for문 무한루프를 탈출)
	captureWg.Wait() // captureWg.Done()을 대기
	fmt.Printf("[저장] %s\n\n", pcapPath)
}