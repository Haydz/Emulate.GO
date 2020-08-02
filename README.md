# Emulate.GO
A tool to abstract away the complexity of executing command line indicators in adversary emulation.


# How to Use - Basics
Use the executable for Windows

Use the ELF binary for Linux

Run with Go: `go run emulation.go`


# TL;DR Usage Example

**Windows**
![](images/image5.png)

**Linux**
![](images/image6.png)


# Video Demonstrations 
Videos might be easier than reading. Please find the link to the demonstrations on YouTube [here](https://www.youtube.com/watch?v=7OV9_Xw5urU&list=PLgdsY7EjXNsaO36rHr8D8cJdP1nlbpVip)

# Standard Usage
## Admin Mode
`go run emulation.go -mode admin -listen 127.0.0.1:9999`

The Admin mode is used to emulate the C2 infrastructure (attacker on an external network). The following functions are available:  
* Execute command line actions manually
* Send a list of commands to be executed


## Client Mode
`go run .\emulation.go -mode client -clientconnect 127.0.0.1:9999`

The client mode will receive commands or list of commands from the Admin (Or parent) interface, then execute on the operating system and send the results back.

### Client List mode
`clientlist`

## Parent Proxy Mode
`go run .\emulation.go -mode parent -parentconnect 127.0.0.1:9999 parentlisten 127.0.0.1:10000`

The Parent Proxy mode acts as a way to forward commands to a third machine. The parent will act as a proxy for commands and command execution results between the Admin interface and client interface.


# List Mode
List mode allows a list of commands to be supplied and executed in sequence.
It requires a file of commands on each new line in a text file. This is used in AdminList Mode.

## Admin List Mode
` go run -mode admin -listen 127.0.0.1:9999 -commands <file>.txt `

## Client List Mode
`go run emulate.go -mode clientlist -clientconnect 127.0.0.1:5555`

## Parent List Mode
For parent mode with a list of commands
`go run emulate.go -mode parentlist -parentconnect 127.0.0.1:4444 -parentlisten 127.0.0.1:5555`



# Admin specific Options:

## -listen
`-listen 127.0.0.1:4444`
Choose which IP and port to listen on

## -logging
`-logging <filename>`
This will add JSON logging to a file from within the Admin interface.

This is to allow documentation of commands executed with timestamps.

Example of JSON output:  
![](images/image1.png)


# Client Mode Specific Options:  

## -clientconnect
The IP and port that the client should connect to.

`-clientconnect 127.0.0.1:4444`



# Parent Specific Options:

## -parentconnect
The IP and port that the parent should connect to the Admin interface on.

`-parentconnect 127.0.0.1:4444`


## -parentlisten
The IP and port that the parent should listen on (for the client to connect).

`-parentlisten 127.0.0.1:5555`




# Generic Options

## -tls
This will add encryption to all modes. The network traffic sent and received will be encrypted with a self signed certificate supplied within the tool itself.


## -skip
This will skip the ENTER requirements when launching each mode. This was added to prevent script kiddies from running the tool.

Example of program pause:

![](images/image4.png)

## -silence
Only available in parent and client modes.
`-silence`

This will cause the parent and client modes to not print anything to the screen.



# Visual Representation of Modes

## Standard Admin and Client

![](images/image2.png)

## Using Parent Proxy Mode

![](images/image3.png)


