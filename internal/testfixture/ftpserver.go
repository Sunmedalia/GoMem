package testfixture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FTPServerOptions defines independent wire-level acquisition controls.
type FTPServerOptions struct {
	FilePaths                                                                    map[string]string
	Files                                                                        map[string][]byte
	PASVOnly, NoSize, NoTime, ChangeSize, ChangeTime, BadCompletion, RejectLogin bool
	ReportedSizeDelta                                                            int64
	TruncateBytes                                                                *int
	Stall                                                                        string // greeting, login, data, final
	Stalled                                                                      chan<- struct{}
}
type FTPServer struct {
	listener    net.Listener
	stop        chan struct{}
	once        sync.Once
	mu          sync.Mutex
	connections []net.Conn
	listeners   []net.Listener
	files       map[string][]byte
	commands    []string
	options     FTPServerOptions
	wg          sync.WaitGroup
	Retrievals  atomic.Int64
}

func StartFTPServer(t testing.TB, options FTPServerOptions) *FTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &FTPServer{listener: listener, stop: make(chan struct{}), options: options, files: map[string][]byte{}}
	for name, data := range options.Files {
		s.files[name] = bytes.Clone(data)
	}
	s.wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.isClosed() {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.connections = append(s.connections, conn)
			s.mu.Unlock()
			s.wg.Go(func() { defer conn.Close(); s.serve(conn) })
		}
	})
	t.Cleanup(s.Close)
	return s
}
func (s *FTPServer) URL() string { return "ftp://" + s.listener.Addr().String() }
func (s *FTPServer) SetFile(name string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[name] = bytes.Clone(data)
}
func (s *FTPServer) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}
func (s *FTPServer) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.listener.Close()
		s.mu.Lock()
		for _, listener := range s.listeners {
			listener.Close()
		}
		for _, conn := range s.connections {
			conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}
func (s *FTPServer) stall(stage string) bool {
	if s.options.Stall != stage {
		return false
	}
	if s.options.Stalled != nil {
		select {
		case s.options.Stalled <- struct{}{}:
		default:
		}
	}
	<-s.stop
	return true
}
func (s *FTPServer) serve(conn net.Conn) {
	if s.stall("greeting") {
		return
	}
	reader := bufio.NewReaderSize(conn, 4096)
	reply := func(format string, args ...any) { fmt.Fprintf(conn, format+"\r\n", args...) }
	reply("220 synthetic FTP fixture")
	cwd := ""
	var passive net.Listener
	defer func() {
		if passive != nil {
			passive.Close()
		}
	}()
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		verb, argument, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		logged := line
		if verb == "PASS" {
			logged = "PASS <redacted>"
		}
		s.mu.Lock()
		s.commands = append(s.commands, logged)
		s.mu.Unlock()
		key := path.Join(cwd, argument)
		if strings.HasPrefix(argument, "/") {
			key = path.Clean(argument)
		}
		s.mu.Lock()
		data, exists := s.files[key]
		s.mu.Unlock()
		sourceSize := int64(len(data))
		diskPath := s.options.FilePaths[key]
		if diskPath != "" {
			info, err := os.Stat(diskPath)
			exists = err == nil && info.Mode().IsRegular()
			if exists {
				sourceSize = info.Size()
			}
		}
		switch verb {
		case "USER":
			if s.stall("login") {
				return
			}
			reply("331 password required")
		case "PASS":
			if s.options.RejectLogin {
				reply("530 rejected secret-password secret-user")
			} else {
				reply("230 logged in")
			}
		case "FEAT":
			if s.options.NoTime {
				reply("211 no extensions")
			} else {
				reply("211-Features\r\n MDTM\r\n211 End")
			}
		case "TYPE":
			if argument == "I" {
				reply("200 binary mode")
			} else {
				reply("504 binary mode required")
			}
		case "OPTS":
			reply("200 option accepted")
		case "CWD":
			if strings.HasPrefix(argument, "/") {
				cwd = path.Clean(argument)
			} else if argument != "." {
				cwd = path.Join(cwd, argument)
			}
			reply("250 directory selected")
		case "SIZE":
			if s.options.NoSize {
				reply("502 SIZE unsupported")
				continue
			}
			if !exists {
				reply("550 absent")
				continue
			}
			size := sourceSize + s.options.ReportedSizeDelta
			if s.options.ChangeSize && s.Retrievals.Load() > 0 {
				size++
			}
			reply("213 %d", size)
		case "MDTM":
			if !exists {
				reply("550 absent")
				continue
			}
			timestamp := "20200102030405"
			if s.options.ChangeTime && s.Retrievals.Load() > 0 {
				timestamp = "20200102030406"
			}
			reply("213 %s", timestamp)
		case "EPSV", "PASV":
			if verb == "EPSV" && s.options.PASVOnly {
				reply("502 EPSV unsupported")
				continue
			}
			if passive != nil {
				passive.Close()
			}
			var err error
			passive, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.isClosed() {
				s.mu.Unlock()
				passive.Close()
				return
			}
			s.listeners = append(s.listeners, passive)
			s.mu.Unlock()
			port := passive.Addr().(*net.TCPAddr).Port
			if verb == "EPSV" {
				reply("229 Entering extended passive mode (|||%d|)", port)
			} else {
				reply("227 Entering passive mode (203,0,113,7,%d,%d)", port/256, port%256)
			}
		case "RETR":
			if !exists {
				reply("550 absent")
				continue
			}
			if passive == nil {
				reply("425 passive connection required")
				continue
			}
			reply("150 binary data follows")
			dataConn, err := passive.Accept()
			passive.Close()
			passive = nil
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.isClosed() {
				s.mu.Unlock()
				dataConn.Close()
				return
			}
			s.connections = append(s.connections, dataConn)
			s.mu.Unlock()
			s.Retrievals.Add(1)
			if s.stall("data") {
				dataConn.Close()
				return
			}
			var stream io.Reader = bytes.NewReader(data)
			var file *os.File
			if diskPath != "" {
				file, err = os.Open(diskPath)
				if err != nil {
					dataConn.Close()
					return
				}
				stream = file
			}
			if s.options.TruncateBytes != nil {
				stream = io.LimitReader(stream, int64(*s.options.TruncateBytes))
			}
			dataConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, _ = io.CopyBuffer(dataConn, stream, make([]byte, 64<<10))
			if file != nil {
				file.Close()
			}
			dataConn.Close()
			if s.stall("final") {
				return
			}
			if s.options.BadCompletion {
				reply("426 transfer incomplete")
			} else {
				reply("226 transfer complete")
			}
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown command " + strconv.Quote(verb))
		}
	}
}

func (s *FTPServer) isClosed() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}
