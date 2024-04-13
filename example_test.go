package goca_test

import (
	"fmt"
	"log"
	"os"

	"github.com/kairoaraujo/goca/v2"
)

func Example_minimal() {

	// Define the GOCAPTH (Default is current dir)
	os.Setenv("CAPATH", "/opt/GoCA/CA")

	// RootCAIdentity for creation
	rootCAIdentity := goca.Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
	}

	// Create the New Root CA or loads existent from disk ($CAPATH)
	RootCA, err := goca.New("mycompany.com", rootCAIdentity)
	if err != nil {
		// Loads in case it exists
		fmt.Println("Loading CA")
		RootCA, err = goca.Load("gocaroot.nl")
		if err != nil {
			log.Fatal(err)
		}

		// Check the CA status and shows the CA Certificate
		fmt.Println(RootCA.Status())
		fmt.Println(RootCA.GetCertificate())

	} else {
		log.Fatal(err)
	}

	// Issue certificate for example intranet server
	intranetIdentity := goca.Identity{
		Organization:       "Intranet Company Inc.",
		OrganizationalUnit: "Global Intranet",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"w3.intranet.example.com", "www.intranet.example.com"},
	}

	intranetCert, err := RootCA.IssueCertificate("intranet.example.com", intranetIdentity)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(intranetCert.GetCertificate())

	// Shows all CA Certificates
	fmt.Println(RootCA.ListCertificates())
}
