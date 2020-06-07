package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func anyLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.To4()
}

func htons(n uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&n))[:])
}

func htonl(n uint32) uint32 {
	return binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&n))[:])
}

type iphdr struct {
	versionAndIhl uint8
	tos           uint8
	totalLength   uint16
	id            uint16
	fragOff       uint16
	ttl           uint8
	protocol      uint8
	checksum      uint16
	srcAddr       uint32
	destAddr      uint32
}

var (
	zeroIPHdr  iphdr
	zeroTCPHdr tcphdr
	zeroPseudo pseudotcphdr
)

const (
	sizeIPHDR        = unsafe.Sizeof(zeroIPHdr)
	sizeTCPHdr       = unsafe.Sizeof(zeroTCPHdr)
	sizePseudoTCPHdr = unsafe.Sizeof(zeroPseudo)
)

func randomIPHdrBytes(srcAddr, destAddr net.IP) [20]byte {
	ip := anyLocalIP()
	versionAndIhl := byte(4)
	versionAndIhl <<= 4
	versionAndIhl |= 5
	iphdr := iphdr{
		versionAndIhl: versionAndIhl,
		tos:           0x0b8,
		totalLength:   htons(40),
		id:            uint16(rand.Intn(math.MaxUint16)),
		fragOff:       0,
		protocol:      syscall.IPPROTO_TCP,
		ttl:           0xff,
		srcAddr:       *(*uint32)(unsafe.Pointer(&ip[0])),
		destAddr:      *(*uint32)(unsafe.Pointer(&destAddr[0])),
	}
	payload := (*[20]byte)(unsafe.Pointer(&iphdr))
	iphdr.checksum = htons(checksum(payload[:]))
	return *payload
}

func checksum(payload []byte) uint16 {
	n := len(payload)
	i := 0
	sum := uint32(0)

	for i = 0; i < n; i += 2 {
		word := uint16(payload[i])
		word <<= 8
		word &= 0xffff
		word |= uint16(payload[i+1])
		sum += uint32(word)
	}

	if i-1 == n {
		sum += uint32(payload[i])
	}

	for carry := sum >> 16; carry != 0; carry = sum >> 16 {
		sum &= 0xffff
		sum += carry
	}

	return ^uint16(sum)
}

type tcphdr struct {
	srcPort uint16
	dstPort uint16
	seq     uint32
	ack     uint32
	thOff   uint8
	flags   uint8
	window  uint16
	sum     uint16
	urp     uint16
}

func (t tcphdr) byte() []byte {
	payload := make([]byte, sizeTCPHdr, sizeTCPHdr)
	arr := *(*[sizeTCPHdr]byte)(unsafe.Pointer(&t))
	copy(payload, arr[:])
	return payload
}

type pseudotcphdr struct {
	srcAddr  uint32
	destAddr uint32
	zero     uint8
	protocol uint8
	length   uint16
}

func (p pseudotcphdr) byte() []byte {
	const sz = unsafe.Sizeof(p)
	payload := make([]byte, sz, sz)
	arr := *(*[sz]byte)(unsafe.Pointer(&p))
	copy(payload, arr[:])
	return payload
}

const (
	syn = byte(0x2)
	rst = byte(0x4)
	ack = byte(0x10)
)

func randomSynBytes(pseudo pseudotcphdr, port uint16) [20]byte {
	tcpheader := tcphdr{
		srcPort: htons(uint16(rand.Intn(math.MaxUint16))),
		dstPort: htons(port),
		seq:     htonl(rand.Uint32()),
		thOff:   0x5 << 4,
		flags:   syn,
		window:  htons(512),
	}
	const sz = sizePseudoTCPHdr + sizeTCPHdr
	payloadSum := make([]byte, sz, sz)
	payloadSum = append(payloadSum, pseudo.byte()...)
	payloadSum = append(payloadSum, tcpheader.byte()...)
	payload := (*[20]byte)(unsafe.Pointer(&tcpheader))
	tcpheader.sum = htons(checksum(payloadSum))
	return *payload
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "[!] Invalid nummber of arguments, please specify host port\n")
		os.Exit(1)
	}
	host := os.Args[1]
	prt, err := strconv.ParseUint(os.Args[2], 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid port, %v\n", err)
		os.Exit(1)
	}
	port := uint16(prt)

	sk, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot create raw socket, %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(sk)
	if err = syscall.SetsockoptInt(sk, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot set ip header include, %v\n", err)
		os.Exit(1)
	}

	ipaddr, err := net.ResolveIPAddr("ip4:tcp", host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot resolve addr, %v\n", err)
		os.Exit(1)
	}

	src := anyLocalIP()
	to := syscall.SockaddrInet4{Port: int(htons(port))}
	dest := ipaddr.IP.To4()
	copy(to.Addr[:], dest)
	payload := make([]byte, 0, 40)
	ipHeaderPayload := randomIPHdrBytes(src, dest)
	payload = append(payload, ipHeaderPayload[:]...)

	srcAddr := *(*uint32)(unsafe.Pointer(&src[0]))
	tcpHeaderPayload := randomSynBytes(pseudotcphdr{
		srcAddr:  srcAddr,
		destAddr: *(*uint32)(unsafe.Pointer(&dest[0])),
		zero:     0,
		protocol: syscall.IPPROTO_TCP,
		length:   htons(uint16(sizeTCPHdr)),
	}, port)
	payload = append(payload, tcpHeaderPayload[:]...)

	if err = syscall.Sendto(sk, payload, 0, &to); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Fail to send payload, %v\n", err)
		os.Exit(1)
	}

	var buffer [1500]byte
	for {
		n, sfrom, err := syscall.Recvfrom(sk, buffer[:], 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Fail, cannot read from socket, %v\n", err)
			os.Exit(1)
		}
		from, ok := sfrom.(*syscall.SockaddrInet4)
		if !ok {
			fmt.Fprintf(os.Stderr, "[!] Peer returned is not ipv4\n")
			os.Exit(1)
		}
		if n < 0 {
			fmt.Fprintf(os.Stderr, "[!] Received malformed packet\n")
			continue
		}
		if from.Addr != to.Addr {
			fmt.Println("[*] Not peer from packet..")
			continue
		}
		// if we're dealing with a syn+ack or rast+ack
		tcphdrp := buffer[sizeIPHDR : sizeIPHDR+sizeTCPHdr]
		tcphdr := *(*tcphdr)(unsafe.Pointer(&tcphdrp[0]))
		switch {
		case tcphdr.flags&(syn|ack) == (syn | ack): // synAck
			fmt.Println("[*] Service is open")
			os.Exit(0)
		case tcphdr.flags&(ack|rst) == (ack | rst): // rstAck
			fmt.Println("[*] Serivce is closed")
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "[*] Cannot scan target\n")
			os.Exit(1)
		}
	}
}
