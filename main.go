package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/things-go/go-socks5"
)

type Config struct {
	Mode               string `json:"mode"`
	QUICAddr           string `json:"quic_addr"`
	TLSCertFile        string `json:"tls_cert_file"`
	TLSKeyFile         string `json:"tls_key_file"`
	SocksAddr          string `json:"socks_addr"`
	QUICPortRange      string `json:"quic_port_range"`
	LogLevel           string `json:"log_level"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
}

const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

var (
	logLevel    = LogLevelInfo
	totalConn   int64
	activeConn  int64
	successConn int64
	errorConn   int64
)

func logf(level string, format string, v ...interface{}) {
	allowed := map[string]int{
		LogLevelDebug: 0,
		LogLevelInfo:  1,
		LogLevelWarn:  2,
		LogLevelError: 3,
	}
	if allowed[level] >= allowed[logLevel] {
		log.Printf("[%s] "+format, append([]interface{}{strings.ToUpper(level)}, v...)...)
	}
}

func main() {
	configFile := flag.String("config", "config.json", "Path ke file konfigurasi JSON")
	flag.Parse()

	file, err := os.Open(*configFile)
	if err != nil {
		logf("error", "Gagal membuka file konfigurasi: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		logf("error", "Gagal decode konfigurasi: %v", err)
		os.Exit(1)
	}
	logLevel = strings.ToLower(cfg.LogLevel)

	switch strings.ToLower(cfg.Mode) {
	case "server":
		runServer(&cfg)
	case "client":
		runClient(&cfg)
	default:
		logf("error", "Mode tidak valid: %s", cfg.Mode)
		os.Exit(1)
	}
}

func runServer(cfg *Config) {
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		logf("error", "Gagal load sertifikat TLS: %v", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-tunnel"},
	}

	listener, err := quic.ListenAddr(cfg.QUICAddr, tlsConfig, nil)
	if err != nil {
		logf("error", "Gagal listen pada %s: %v", cfg.QUICAddr, err)
		os.Exit(1)
	}
	logf("info", "Server QUIC mendengarkan pada %s", cfg.QUICAddr)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			logf("info", "Stats - Total: %d | Aktif: %d | Sukses: %d | Error: %d",
				atomic.LoadInt64(&totalConn),
				atomic.LoadInt64(&activeConn),
				atomic.LoadInt64(&successConn),
				atomic.LoadInt64(&errorConn))
		}
	}()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logf("error", "Gagal menerima connection: %v", err)
			continue
		}
		go handleQUICConnection(conn, cfg)
	}
}

func handleQUICConnection(conn quic.Connection, cfg *Config) {
	defer conn.CloseWithError(0, "closed")
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			logf("error", "Gagal menerima stream: %v", err)
			return
		}
		go handleStream(stream, cfg)
	}
}

func handleStream(stream quic.Stream, cfg *Config) {
	atomic.AddInt64(&totalConn, 1)
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)
	defer stream.Close()

	reader := bufio.NewReader(stream)
	targetLine, err := reader.ReadString('\n')
	if err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Gagal membaca alamat tujuan: %v", err)
		return
	}

	target := strings.TrimSpace(targetLine)
	if _, _, err := net.SplitHostPort(target); err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Alamat target tidak valid: %q (%v)", target, err)
		return
	}

	logf("info", "Meneruskan koneksi ke %s", target)

	tcpConn, err := net.Dial("tcp", target)
	if err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Gagal menghubungkan ke %s: %v", target, err)
		return
	}
	defer tcpConn.Close()
	atomic.AddInt64(&successConn, 1)

	if cfg.IdleTimeoutSeconds > 0 {
		deadline := time.Now().Add(time.Duration(cfg.IdleTimeoutSeconds) * time.Second)
		stream.SetDeadline(deadline)
		tcpConn.SetDeadline(deadline)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, err := io.Copy(tcpConn, reader)
		if err != nil {
			logf("debug", "QUIC → TCP error: %v", err)
		}
		cancel()
	}()

	go func() {
		_, err := io.Copy(stream, tcpConn)
		if err != nil {
			logf("debug", "TCP → QUIC error: %v", err)
		}
		cancel()
	}()

	<-ctx.Done()
	logf("debug", "Selesai koneksi ke %s", target)
}

func runClient(cfg *Config) {
	dialer := &QUICDialer{
		quicAddr:  cfg.QUICAddr,
		portRange: cfg.QUICPortRange,
	}

	socksServer := socks5.NewServer(
		socks5.WithDial(dialer.Dial),
	)

	logf("info", "Client SOCKS5 mendengarkan pada %s", cfg.SocksAddr)
	if err := socksServer.ListenAndServe("tcp", cfg.SocksAddr); err != nil {
		logf("error", "Error menjalankan SOCKS5 server: %v", err)
		os.Exit(1)
	}
}

type QUICDialer struct {
	quicAddr  string
	portRange string
}

func (d *QUICDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var minPort, maxPort int
	_, err := fmt.Sscanf(d.portRange, "%d-%d", &minPort, &maxPort)
	if err != nil {
		return nil, fmt.Errorf("invalid port range: %v", err)
	}

	// Generate random port dalam range yang ditentukan
	port := rand.Intn(maxPort-minPort+1) + minPort
	targetAddr := fmt.Sprintf("%s:%d", strings.Split(d.quicAddr, ":")[0], port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-tunnel"},
	}

	conn, err := quic.DialAddr(ctx, targetAddr, tlsConfig, nil)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "stream failed")
		return nil, err
	}

	if _, err := stream.Write([]byte(addr + "\n")); err != nil {
		stream.Close()
		return nil, err
	}

	return &quicStreamConn{Stream: stream, sess: conn}, nil
}

type quicStreamConn struct {
	quic.Stream
	sess quic.Connection
}

func (c *quicStreamConn) Close() error {
	err := c.Stream.Close()
	c.sess.CloseWithError(0, "closed")
	return err
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	if udpAddr, ok := c.sess.LocalAddr().(*net.UDPAddr); ok {
		return &net.TCPAddr{
			IP:   udpAddr.IP,
			Port: udpAddr.Port,
			Zone: udpAddr.Zone,
		}
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	return c.sess.RemoteAddr()
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	return c.Stream.SetDeadline(t)
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	return c.Stream.SetReadDeadline(t)
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.Stream.SetWriteDeadline(t)
}
