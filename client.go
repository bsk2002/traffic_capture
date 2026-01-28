package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"crypto/tls"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func findActiveInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	// 1순위: IP가 있고 Loopback이 아닌 실제 장치 찾기
	for _, device := range devices {
		for _, addr := range device.Addresses {
			// IP가 있고(IPv4), 루프백(127.0.0.1)이 아닌 것
			if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
				return device.Name, nil
			}
		}
	}

	// 2순위: 적당한 걸 못 찾으면 목록의 첫 번째 장치 반환 (fallback)
	if len(devices) > 0 {
		return devices[0].Name, nil
	}

	return "", fmt.Errorf("no interfaces found")
}

func main() {

	// Configuration Variable
	targetURL := os.Args[1]
	outputFile := os.Args[2]
	deviceName, err := findActiveInterface()

	if err != nil {
		log.Fatal("네트워크 인터페이스 탐색 실패:", err)
	}
	fmt.Printf(">>> Auto-detected Interface: %s\n", deviceName)

	snapshotLen := int32(1600)
	promiscuous := false
	errTimeout := pcap.BlockForever // control in select state
	// now := time.Now().Format("20060102_150405")
	// outputFile := fmt.Sprintf("website_capture_%s.pcap", now)

	// DNS lookup
	u, err := url.Parse(targetURL)
	if err != nil {
		log.Fatal("URL parsing failed:", err)
	}

	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Fatal("IP lookup failed:", err)
	}

	var filterParts []string
	var ipList []string

	for _, ip := range ips {
		ipStr := ip.String()
		ipList = append(ipList, ipStr)
		filterParts = append(filterParts, fmt.Sprintf("host %s", ipStr))
	}

	if len(filterParts) == 0 {
		log.Fatal("No IPs found for host")
	}

	// ex: "host 104[.]18[.]26[.]120 or host 2606:4700::6812:1b78"
	finalFilter := strings.Join(filterParts, " or ")

	fmt.Printf("Target: %s\n", host)
	fmt.Printf("Resolved IPs: %v\n", ipList)
	fmt.Printf("BPF Filter: %s\n", finalFilter)

	f, err := os.Create(outputFile) // os.Create(fineName)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		f.Close()
		fmt.Println("\n>>> [System] File closed cleanly.")
	}()

	pcapWriter := pcapgo.NewWriter(f)

	err = pcapWriter.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
	if err != nil {
		log.Fatal(err)
	}

	// OpenLive: oepn a live capture.
	// pcap.OpenLive(interface, snaplen, promiscuous, timeout)
	// return: handle, error
	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, errTimeout)
	if err != nil {
		log.Printf("디바이스 %s를 여는 데 실패했습니다: %v", deviceName, err)
		log.Fatal("올바른 인터페이스 이름을 확인하거나 관리자 권한(sudo)으로 실행하세요.")
	}
	defer handle.Close()

	// BPFFilter:
	// TargetIP -> Copy to Application
	// Others -> Drop (Ignore)
	if err := handle.SetBPFFilter(finalFilter); err != nil {
		log.Fatal("Failed applying filter:", err)
	}

	isSuccess := false // if success
	appDone := make(chan bool, 1)

	go func() {
		// waiting 1 second for make packetSource
		fmt.Println(">>> Attemp to connect the website after 1 second...")
		time.Sleep(1 * time.Second)
                
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13, // 최소 버전 TLS 1.3
			MaxVersion: tls.VersionTLS13, // 최대 버전 TLS 1.3
			ServerName: host,             // SNI 설정
		}
		
		tr := &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   tlsConfig,
			/*
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// TCP connect
				conn, err := net.DialTimeout(network, addr, 10*time.Second)
				if err != nil {
					return nil, err
				}

				// wrapping utls client (using HelloCustom mode)
				uConn := utls.UClient(conn, &utls.Config{
					ServerName: host, // SNI setting
				}, utls.HelloCustom)

				//[Datail] deploying GREASE
				spec := &utls.ClientHelloSpec{
					// CipherSuites
					CipherSuites: []uint16{
						utls.GREASE_PLACEHOLDER,
						utls.TLS_AES_128_GCM_SHA256,
						utls.TLS_AES_256_GCM_SHA384,
						utls.GREASE_PLACEHOLDER,
						utls.TLS_CHACHA20_POLY1305_SHA256,
					},
					CompressionMethods: []uint8{0}, // no compression

					// Extensions
					Extensions: []utls.TLSExtension{
						&utls.UtlsGREASEExtension{},
						&utls.SNIExtension{},
						&utls.UtlsGREASEExtension{},
						&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
						&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
						&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
							{Group: utls.X25519},
						}},
						&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
							utls.ECDSAWithP256AndSHA256,
							utls.PSSWithSHA256,
						}},
					},
				}

				if err := uConn.ApplyPreset(spec); err != nil {
					return nil, err
				}

				// handshake
				if err := uConn.Handshake(); err != nil {
					return nil, err
				}

				return uConn, nil
			},
			*/
		}
		client := http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}

		resp, err := client.Get(targetURL)
		if err != nil {
			log.Printf("Connection error: %v", err)
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // trigger FIN or Close_Notify
			fmt.Printf(">>> [Client] Complete loading (Status: %d)\n", resp.StatusCode)
			isSuccess = true
		}

		appDone <- true
	}()

	// NewPacketSource(): create packet data source
	// handle: read packet data
	// handle.LinkType(): select decoder automatic
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets() // incoming channel for packet

	fmt.Println("--- Starting Capture (Automatic shutdown when loading website) ---")

	packetCount := 0

	// Flags
	isClosingMode := false // loading website done
	isDraining := false    // after FIN

	maxTeardownWait := 5 * time.Second
	teardownTimer := time.NewTimer(maxTeardownWait)
	teardownTimer.Stop()

Loop:
	for {
		select {
		case <-appDone:
			fmt.Println("\n>>> [System] Get shutdown signal. Watching Teardown(FIN/RST)")
			isClosingMode = true
			teardownTimer.Reset(maxTeardownWait)

		case <-teardownTimer.C:
			if isDraining {
				fmt.Println("\n>>> [System] Draining complete. Capture finished.")
			} else {
				fmt.Println("\n>>> [System] Timeout. Connection kept alive orunexpected delay.")
			}
			break Loop

		case packet := <-packetChan:
			if packet == nil {
				break Loop
			}

			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Printf("Write Error: %v", err)
			}
			packetCount++
			fmt.Printf("\rCaptured: %d packets | Last Size: %d bytes", packetCount, len(packet.Data()))

			if isClosingMode && !isDraining {
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)

					// check if there is FIN/RST flag or not
					if tcp.FIN || tcp.RST {
						fmt.Println("\n>>> [System] Found FIN/RST packet.")
						fmt.Println(">>> [System] Waitint 1s for remaining packets (ACKs)...")

						isDraining = true
						teardownTimer.Reset(1 * time.Second)
					}
				}
			}
		}
	}

	// 경고: 패킷이 0개면 인터페이스 문제일 수 있음
	if packetCount == 0 {
		fmt.Println("\n\n[Error] 0 Packets captured! Check Interface or VPN.")
		// defer f.Close()를 강제 실행시키기 위해 return 사용 (os.Exit은 defer 무시함)
		return
	}

	fmt.Printf("\nSaved File: %s\n", outputFile)

	if isSuccess {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

