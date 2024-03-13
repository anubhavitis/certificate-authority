package main

import (
	ca "certi/src/services/CA"
	"certi/src/services/certificates"
	"fmt"
	"net"
)

func main() {
	fmt.Println("Hello, World!")
	ca := ca.GetCA()
	fmt.Println(" My Ca is: ", ca)

	err := certificates.CreateCertificate(net.IPv4(127, 0, 0, 1))
	if err != nil {
		fmt.Println("Error: ", err)
	}

}
