package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var address = flag.String("a", "0.0.0.0", "address")
	var port = flag.String("p", "2222", "port")
	var fileName = flag.String("l", "ssh-honeypot.log", "output file")
	var toConsole = flag.Bool("console", false, "Don't log to a file")

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

	_, keyBytes, _ := ed25519.GenerateKey(nil)
	key, err := ssh.NewSignerFromSigner(keyBytes)
	if err != nil {
		log.Fatal("Failed to generate new ssh key: ", err.Error())
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			log.Print(connection.RemoteAddr(), " User: ", connection.User())
			log.Print(connection.RemoteAddr(), " Password: ", string(password))
			return nil, nil
		},
	}
	serverConfig.AddHostKey(key)

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
		term.Write([]byte("Welcome back commander\n"))
		for {
			line, err := term.ReadLine()
			if err == io.EOF {
				channel.SendRequest("exit-status", false,
					ssh.Marshal(struct{ Status uint32 }{0}))
				log.Print("Exiting channel ", err.Error())
				break
			} else if err != nil {
				log.Print("Error creating terminal ", err.Error())
				break
			}
			log.Print("[", conn.RemoteAddr(), "]$ ", line)
		}
	} else {
		log.Print("Non session channel received.")
	}
}
