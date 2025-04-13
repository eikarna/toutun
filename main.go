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
	"sync"
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

// streamConnWrapper membungkus quic.Stream agar dapat digunakan sebagai net.Conn.
type streamConnWrapper struct {
	quic.Stream
}

func (s *streamConnWrapper) LocalAddr() net.Addr {
	// Mengembalikan alamat dummy, karena quic.Stream tidak menyediakan informasi ini.
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (s *streamConnWrapper) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (s *streamConnWrapper) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}

func (s *streamConnWrapper) SetReadDeadline(t time.Time) error {
	return s.Stream.SetReadDeadline(t)
}

func (s *streamConnWrapper) SetWriteDeadline(t time.Time) error {
	return s.Stream.SetWriteDeadline(t)
}

func runServer(cfg *Config) {
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		logf("error", "Gagal load sertifikat TLS: %v", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"toutun"},
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout: time.Duration(cfg.IdleTimeoutSeconds) * time.Second,
		Allow0RTT:      true,
	}

	listener, err := quic.ListenAddr(cfg.QUICAddr, tlsConfig, quicConfig)
	if err != nil {
		logf("error", "Gagal listen pada %s: %v", cfg.QUICAddr, err)
		os.Exit(1)
	}
	logf("info", "Server QUIC mendengarkan pada %s", cfg.QUICAddr)

	// Tampilkan statistik koneksi secara periodik.
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
	// Pastikan connection ditutup saat selesai.
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

// readHeader membaca satu baris (hingga '\n') dari conn dan mengembalikan sisa data yang sudah ter-buffer.
func readHeader(conn net.Conn) (header string, buffered net.Conn, err error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(line), &bufferedConn{Reader: reader, Conn: conn}, nil
}

func handleStream(stream quic.Stream, cfg *Config) {
	atomic.AddInt64(&totalConn, 1)
	atomic.AddInt64(&activeConn, 1)
	// Pastikan stream selalu ditutup agar resource dilepas.
	defer stream.Close()
	defer atomic.AddInt64(&activeConn, -1)

	// Bungkus stream dengan wrapper agar mendukung net.Conn.
	connWrapper := &streamConnWrapper{stream}

	// Baca header target (alamat tujuan) yang dikirim secara plaintext.
	target, bufferedStream, err := readHeader(connWrapper)
	if err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Gagal membaca header target: %v", err)
		return
	}

	// Validasi format alamat.
	if _, _, err := net.SplitHostPort(target); err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Alamat target tidak valid: %q (%v)", target, err)
		return
	}

	logf("info", "Meneruskan koneksi ke %s", target)

	// Hubungkan ke target TCP.
	tcpConn, err := net.Dial("tcp", target)
	if err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Gagal menghubungkan ke %s: %v", target, err)
		return
	}
	defer tcpConn.Close()
	atomic.AddInt64(&successConn, 1)

	// Atur deadline jika dikonfigurasi.
	if cfg.IdleTimeoutSeconds > 0 {
		deadline := time.Now().Add(time.Duration(cfg.IdleTimeoutSeconds) * time.Second)
		bufferedStream.SetDeadline(deadline)
		tcpConn.SetDeadline(deadline)
	}

	// Gunakan WaitGroup untuk transfer data dua arah.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(tcpConn, bufferedStream); err != nil {
			logf("debug", "QUIC → TCP error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(bufferedStream, tcpConn); err != nil {
			logf("debug", "TCP → QUIC error: %v", err)
		}
	}()

	wg.Wait()
	logf("debug", "Selesai koneksi ke %s", target)
}

func runClient(cfg *Config) {
	dialer := &QUICDialer{
		quicAddr:  cfg.QUICAddr,
		portRange: cfg.QUICPortRange,
		idleSec:   cfg.IdleTimeoutSeconds,
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
	idleSec   int
}

func (d *QUICDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var minPort, maxPort int
	_, err := fmt.Sscanf(d.portRange, "%d-%d", &minPort, &maxPort)
	if err != nil {
		return nil, fmt.Errorf("invalid port range: %v", err)
	}

	// Pilih port secara acak dalam rentang yang diberikan.
	port := rand.Intn(maxPort-minPort+1) + minPort
	targetAddr := fmt.Sprintf("%s:%d", strings.Split(d.quicAddr, ":")[0], port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"toutun"},
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout: time.Duration(d.idleSec) * time.Second,
		Allow0RTT:      true,
	}

	conn, err := quic.DialAddr(ctx, targetAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "stream failed")
		return nil, err
	}

	// Kirim header target address secara plaintext untuk mendukung 0-RTT/early data.
	if _, err := stream.Write([]byte(addr + "\n")); err != nil {
		stream.Close()
		return nil, err
	}

	// Bungkus stream dengan wrapper agar bisa digunakan sebagai net.Conn.
	connWrapper := &streamConnWrapper{stream}
	return &quicStreamConn{Stream: stream, sess: conn, wrapped: connWrapper}, nil
}

type quicStreamConn struct {
	quic.Stream
	sess    quic.Connection
	wrapped net.Conn
}

func (c *quicStreamConn) Read(b []byte) (int, error) {
	return c.wrapped.Read(b)
}

func (c *quicStreamConn) Write(b []byte) (int, error) {
	return c.wrapped.Write(b)
}

func (c *quicStreamConn) Close() error {
	err := c.wrapped.Close()
	c.sess.CloseWithError(0, "closed")
	return err
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	return c.wrapped.LocalAddr()
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	return c.sess.RemoteAddr()
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	return c.wrapped.SetDeadline(t)
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	return c.wrapped.SetReadDeadline(t)
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.wrapped.SetWriteDeadline(t)
}

type bufferedConn struct {
	Reader *bufio.Reader
	Conn   net.Conn
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.Reader.Read(p)
}

func (bc *bufferedConn) Write(p []byte) (int, error) {
	return bc.Conn.Write(p)
}

func (bc *bufferedConn) Close() error {
	return bc.Conn.Close()
}

func (bc *bufferedConn) LocalAddr() net.Addr {
	return bc.Conn.LocalAddr()
}

func (bc *bufferedConn) RemoteAddr() net.Addr {
	return bc.Conn.RemoteAddr()
}

func (bc *bufferedConn) SetDeadline(t time.Time) error {
	return bc.Conn.SetDeadline(t)
}

func (bc *bufferedConn) SetReadDeadline(t time.Time) error {
	return bc.Conn.SetReadDeadline(t)
}

func (bc *bufferedConn) SetWriteDeadline(t time.Time) error {
	return bc.Conn.SetWriteDeadline(t)
}
