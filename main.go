package main

import (
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
	"golang.org/x/crypto/ssh/terminal"
)

// RFC 4254 Section 6.5.
type execPayload struct {
	Command string
}

func getIP(networkStr string) string {
	portPattern := regexp.MustCompile(":\\d+$")
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
		PasswordCallback: func(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ipStr := getIP(connection.RemoteAddr().String())
			if tries, exits := triesPerIP[ipStr]; exits {
				triesPerIP[ipStr] = tries + 1
			} else {
				triesPerIP[ipStr] = 1
			}
			log.Print(connection.RemoteAddr(), " User: ", connection.User())
			log.Print(connection.RemoteAddr(), " Password: ", string(password))
			log.Print(connection.RemoteAddr(), " Attempts: ", triesPerIP[ipStr])
			if *attempts == -1 || triesPerIP[ipStr] < *attempts { // Always fail auth
				return nil, fmt.Errorf("password rejected for %q", connection.User())
			}
			return nil, nil
		},
		BannerCallback: func(connection ssh.ConnMetadata) string {
			return *banner + "\n"
		},
	}

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
		log.Fatal("Failed to generate new ssh key: ", err.Error())
	}

	serverConfig.AddHostKey(sshKey)

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
		log.Print("Failed to establish SSH connection. ", err.Error())
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
	log.Print("Channel type ", newChannel.ChannelType())
	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		log.Print("Failed to accept channel ", err.Error())
		return
	}
	defer channel.Close()

	go func(channelRequests <-chan *ssh.Request) {
		for request := range channelRequests {
			log.Print(conn.RemoteAddr(), ":: request type: ", request.Type)
			if request.Type == "exec" {
				var payload execPayload
				if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
					log.Print("Failed to unmarshal exec payload", err)
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
					log.Print("Failed request reply ", err.Error())
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
		log.Print(conn.RemoteAddr(), " Non session channel received.")
	}
}
