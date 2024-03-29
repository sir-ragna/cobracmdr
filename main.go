package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"
)

// RFC 4254 Section 6.5.
type execPayload struct {
	Command string
}

var portPattern = regexp.MustCompile(`:\d+$`)

func getIP(networkStr string) string {
	return portPattern.ReplaceAllString(networkStr, "")
}

func main() {
	var address = flag.String("a", "0.0.0.0", "address")
	var port = flag.String("p", "2222", "port")
	var fileName = flag.String("l", "ssh-honeypot.log", "output file")
	var toConsole = flag.Bool("console", false, "Don't log to a file")
	var attempts = flag.Int64("attempts", 0, "Logging attempts to stop before allowing sign in. (-1 never)")
	var banner = flag.String("banner", "Restricted to authorized users only.", "SSH pre-auth banner")

	// Hold attempts per IP
	var triesPerIP = make(map[string]int64)

	flag.Parse()

	if !*toConsole {
		logFile, err := os.OpenFile(*fileName,
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("Error opening logfile: ", err.Error())
		}
		defer logFile.Close()
		log.Print("Logging to ", *fileName)
		log.SetOutput(logFile)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ipStr := getIP(conn.RemoteAddr().String())
			if tries, exits := triesPerIP[ipStr]; exits {
				triesPerIP[ipStr] = tries + 1
			} else {
				triesPerIP[ipStr] = 1
			}
			log.Print(conn.RemoteAddr(), " User: ", conn.User())
			log.Print(conn.RemoteAddr(), " Password: ", string(password))
			log.Print(conn.RemoteAddr(), " Attempts: ", triesPerIP[ipStr])

			if *attempts == -1 || triesPerIP[ipStr] < *attempts {
				return nil, fmt.Errorf("password rejected for %q", conn.User()) // fail auth
			}
			return nil, nil // accept password
		},
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return *banner + "\n"
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Print(conn.RemoteAddr(), "PublicKey auth attempt type: ", key.Type())
			return nil, nil // accept any public key
		},
	}

	{ // Generate and add RSA key
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal("Failed to generate new rsa key: ", err.Error())
		}

		log.Print("Private key: ", strings.ReplaceAll(
			string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			})), "\n", ""))

		log.Print("Public key: ", strings.ReplaceAll(
			string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
			})), "\n", ""))

		sshKey, err := ssh.NewSignerFromKey(rsaKey)
		if err != nil {
			log.Fatal("Failed to generate new RSA ssh key: ", err.Error())
		}

		serverConfig.AddHostKey(sshKey)
	} // end of RSA key generation

	{ // Generate ed25519 key
		ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal("Failed to generate a new ed25519 key: ", err.Error())
		}
		log.Print("Private key: ", strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{
			Type:  "ED25519 PRIVATE KEY",
			Bytes: []byte(ed25519PrivateKey),
		})), "\n", ""))

		log.Print("Public key: ", strings.ReplaceAll(
			string(pem.EncodeToMemory(&pem.Block{
				Type:  "ED25519 PUBLIC KEY",
				Bytes: []byte(ed25519PublicKey),
			})), "\n", ""))

		sshKey, err := ssh.NewSignerFromKey(ed25519PrivateKey)
		if err != nil {
			log.Fatal("Failed to generate new ed25519 ssh key: ", err.Error())
		}

		serverConfig.AddHostKey(sshKey)
	} // end of ed25519 key generation

	{ // Generate and add EC P256 key
		ecP224, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal("Failed to generate new EC P256 key: ", err.Error())
		}

		log.Print("Private key: ", strings.ReplaceAll(
			string(pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: ecP224.X.Bytes(),
			})), "\n", ""))

		log.Print("Public key: ", strings.ReplaceAll(
			string(pem.EncodeToMemory(&pem.Block{
				Type:  "EC PUBLIC KEY",
				Bytes: ecP224.PublicKey.X.Bytes(),
			})), "\n", ""))

		sshKey, err := ssh.NewSignerFromKey(ecP224)
		if err != nil {
			log.Fatal("Failed to generate new EC P256 ssh key: ", err.Error())
		}

		serverConfig.AddHostKey(sshKey)
	} // end of EC P256 key generation

	listener, err := net.Listen("tcp", *address+":"+*port)
	if err != nil {
		log.Fatal("Failed to listen: ", err.Error())
	}
	log.Print("Started honeypot on: ", *address+":"+*port)
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Failed to accept connection: ", err.Error())
			continue
		}

		go handleConnection(conn, serverConfig)
	}
}

func handleConnection(conn net.Conn, serverConfig *ssh.ServerConfig) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		log.Print(conn.RemoteAddr(), " Failed to establish SSH connection. ", err.Error())
		return
	}
	log.Print("Established SSH connection. ", conn.RemoteAddr())

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		go handleChannel(newChannel, conn)
	}
	log.Print("Client disconnected ", conn.RemoteAddr())
}

func handleChannel(newChannel ssh.NewChannel, conn net.Conn) {
	log.Print(conn.RemoteAddr(), "::Channel type ", newChannel.ChannelType())

	if newChannel.ChannelType() == "direct-tcpip" {
		log.Print(conn.RemoteAddr(), "::Rejecting direct-tcpip channel")
		newChannel.Reject(ssh.Prohibited, "direct tcpip channels are not allowed")
		return
	}

	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		log.Print(conn.RemoteAddr(), " Failed to accept channel ", err.Error())
		return
	}
	defer channel.Close()

	go func(channelRequests <-chan *ssh.Request) {
		for request := range channelRequests {
			log.Print(conn.RemoteAddr(), ":: request type: ", request.Type)
			if request.Type == "exec" {
				var payload execPayload
				if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
					log.Print(conn.RemoteAddr(), " Failed to unmarshal exec payload", err)
					str := base64.StdEncoding.EncodeToString(request.Payload)
					log.Print(conn.RemoteAddr(), "::exec payload b64:\t", str)
				} else {
					log.Print(conn.RemoteAddr(), "::exec payload:\t", payload.Command)
				}
			} else {
				str := base64.StdEncoding.EncodeToString(request.Payload)
				log.Print(conn.RemoteAddr(), ":: payload b64:\t", str)
			}
			if request.WantReply {
				err := request.Reply(true, nil)
				if err != nil {
					log.Print(conn.RemoteAddr(), " Failed request reply ", err.Error())
				}
			}
		}
	}(channelRequests)

	if newChannel.ChannelType() == "session" {
		term := terminal.NewTerminal(channel, "[CMDR@COBRA] $ ")
		for {
			line, err := term.ReadLine()
			if err == io.EOF {
				channel.SendRequest("exit-status", false,
					ssh.Marshal(struct{ Status uint32 }{0}))
				log.Print(conn.RemoteAddr(), " Exiting channel ", err.Error())
				break
			} else if err != nil {
				log.Print(conn.RemoteAddr(), " Error creating terminal ", err.Error())
				break
			}
			log.Print("[", conn.RemoteAddr(), "]$ ", line)
		}
	} else {
		log.Print("Non session channel received from ", conn.RemoteAddr())
	}
}
