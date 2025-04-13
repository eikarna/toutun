package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
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
	"golang.org/x/crypto/chacha20poly1305"
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
	PreSharedKey       string `json:"pre_shared_key"`
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

	// Pastikan pre-shared key memiliki panjang 32 byte untuk ChaCha20-Poly1305.
	var sharedKey []byte
	if len(cfg.PreSharedKey) == 32 {
		sharedKey = []byte(cfg.PreSharedKey)
	} else {
		// Fallback demo key (tidak aman untuk produksi)
		sharedKey = []byte("0123456789abcdef0123456789abcdef")
	}

	switch strings.ToLower(cfg.Mode) {
	case "server":
		runServer(&cfg, sharedKey)
	case "client":
		runClient(&cfg, sharedKey)
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

func runServer(cfg *Config, sharedKey []byte) {
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
		go handleQUICConnection(conn, cfg, sharedKey)
	}
}

func handleQUICConnection(conn quic.Connection, cfg *Config, sharedKey []byte) {
	defer conn.CloseWithError(0, "closed")
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			logf("error", "Gagal menerima stream: %v", err)
			return
		}
		go handleStream(stream, cfg, sharedKey)
	}
}

// readHeader membaca satu baris (hingga '\n') dari conn dan mengembalikan sisa data yang telah ter-buffer.
func readHeader(conn net.Conn) (header string, buffered net.Conn, err error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(line), &bufferedConn{Reader: reader, Conn: conn}, nil
}

func handleStream(stream quic.Stream, cfg *Config, sharedKey []byte) {
	atomic.AddInt64(&totalConn, 1)
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// Bungkus stream dengan wrapper agar mendukung net.Conn.
	connWrapper := &streamConnWrapper{stream}
	// Header target dikirim plaintext untuk 0-RTT/0.5-RTT.
	target, bufferedStream, err := readHeader(connWrapper)
	if err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Gagal membaca header target: %v", err)
		stream.Close()
		return
	}

	if _, _, err := net.SplitHostPort(target); err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Alamat target tidak valid: %q (%v)", target, err)
		stream.Close()
		return
	}

	logf("info", "Meneruskan koneksi ke %s", target)

	tcpConn, err := net.Dial("tcp", target)
	if err != nil {
		atomic.AddInt64(&errorConn, 1)
		logf("error", "Gagal menghubungkan ke %s: %v", target, err)
		stream.Close()
		return
	}
	defer tcpConn.Close()
	atomic.AddInt64(&successConn, 1)

	if cfg.IdleTimeoutSeconds > 0 {
		deadline := time.Now().Add(time.Duration(cfg.IdleTimeoutSeconds) * time.Second)
		bufferedStream.SetDeadline(deadline)
		tcpConn.SetDeadline(deadline)
	}

	// Bungkus koneksi sisa stream dengan enkripsi ChaCha20-Poly1305.
	encryptedStream, err := newEncryptedConn(bufferedStream, sharedKey)
	if err != nil {
		logf("error", "Gagal membuat koneksi terenkripsi: %v", err)
		stream.Close()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, err := io.Copy(tcpConn, encryptedStream)
		if err != nil {
			logf("debug", "Encrypted QUIC → TCP error: %v", err)
		}
		cancel()
	}()

	go func() {
		_, err := io.Copy(encryptedStream, tcpConn)
		if err != nil {
			logf("debug", "TCP → Encrypted QUIC error: %v", err)
		}
		cancel()
	}()

	<-ctx.Done()
	logf("debug", "Selesai koneksi ke %s", target)
}

func runClient(cfg *Config, sharedKey []byte) {
	dialer := &QUICDialer{
		quicAddr:  cfg.QUICAddr,
		portRange: cfg.QUICPortRange,
		sharedKey: sharedKey,
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
	sharedKey []byte
	idleSec   int
}

func (d *QUICDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var minPort, maxPort int
	_, err := fmt.Sscanf(d.portRange, "%d-%d", &minPort, &maxPort)
	if err != nil {
		return nil, fmt.Errorf("invalid port range: %v", err)
	}

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

	// Kirim header target address secara plaintext untuk 0-RTT/early data.
	if _, err := stream.Write([]byte(addr + "\n")); err != nil {
		stream.Close()
		return nil, err
	}

	// Bungkus stream dengan wrapper agar bisa digunakan sebagai net.Conn,
	// lalu bungkus lagi dengan enkripsi ChaCha20-Poly1305.
	connWrapper := &streamConnWrapper{stream}
	encryptedStream, err := newEncryptedConn(connWrapper, d.sharedKey)
	if err != nil {
		stream.Close()
		return nil, err
	}

	return &quicStreamConn{Stream: stream, sess: conn, wrapped: encryptedStream}, nil
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

// ---- Implementasi encryptedConn ----

type encryptedConn struct {
	conn         net.Conn
	aead         cipher.AEAD
	writeMutex   sync.Mutex
	readMutex    sync.Mutex
	readBuf      bytes.Buffer
	writeCounter uint64
}

func newEncryptedConn(conn net.Conn, key []byte) (net.Conn, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &encryptedConn{
		conn: conn,
		aead: aead,
	}, nil
}

func (ec *encryptedConn) Read(p []byte) (int, error) {
	ec.readMutex.Lock()
	defer ec.readMutex.Unlock()

	if ec.readBuf.Len() > 0 {
		return ec.readBuf.Read(p)
	}

	lenBytes := make([]byte, 4)
	if _, err := io.ReadFull(ec.conn, lenBytes); err != nil {
		return 0, err
	}
	msgLen := binary.BigEndian.Uint32(lenBytes)
	if msgLen < uint32(ec.aead.NonceSize()) {
		return 0, fmt.Errorf("pesan terenkripsi terlalu pendek")
	}

	encData := make([]byte, msgLen)
	if _, err := io.ReadFull(ec.conn, encData); err != nil {
		return 0, err
	}
	nonce := encData[:ec.aead.NonceSize()]
	ciphertext := encData[ec.aead.NonceSize():]
	plaintext, err := ec.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}
	ec.readBuf.Write(plaintext)
	return ec.readBuf.Read(p)
}

func (ec *encryptedConn) Write(p []byte) (int, error) {
	ec.writeMutex.Lock()
	defer ec.writeMutex.Unlock()

	nonce := make([]byte, ec.aead.NonceSize())
	// 4 byte pertama tetap 0, 8 byte berikutnya dari counter.
	binary.BigEndian.PutUint64(nonce[4:], ec.writeCounter)
	ec.writeCounter++

	ciphertext := ec.aead.Seal(nil, nonce, p, nil)
	msg := append(nonce, ciphertext...)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(msg)))
	if _, err := ec.conn.Write(lenBytes); err != nil {
		return 0, err
	}
	if _, err := ec.conn.Write(msg); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (ec *encryptedConn) Close() error {
	return ec.conn.Close()
}

func (ec *encryptedConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

func (ec *encryptedConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

func (ec *encryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

func (ec *encryptedConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

func (ec *encryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

// ---- Buffered connection wrapper agar data yang sudah ter-read oleh bufio.Reader tidak hilang ----

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
