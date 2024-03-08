package main

import (
	"flag"
	"fmt"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/kairoaraujo/goca/v2/docs"
	"github.com/kairoaraujo/goca/v2/rest-api/controllers"
)

// @title GoCA API
// @description GoCA Certificate Authority Management API.
// @schemes http https
// @securityDefinitions.basic BasicAuth

// @contact.name GoCA API Issues Report
// @contact.url http://github.com/kairoaraujo/goca/issues

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
func main() {

	var port int

	flag.IntVar(&port, "p", 80, "Port to listen, default is 80")
	flag.Parse()

	router := gin.Default()
	// Set a lower memory limit for multipart forms (default is 32 MiB)
	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.Use(gin.Logger())
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := router.Group("/api")
	v1 := api.Group("/v1")

	// Routes
	v1.GET("/ca", controllers.GetCA)
	v1.POST("/ca", controllers.AddCA)
	v1.GET("/ca/:cn", controllers.GetCACommonName)
	v1.POST("/ca/:cn/sign", controllers.SignCSR)
	v1.POST("/ca/:cn/upload", controllers.UploadCertificateICA)
	v1.GET("/ca/:cn/certificates", controllers.GetCertificates)
	v1.POST("/ca/:cn/certificates", controllers.IssueCertificates)
	v1.DELETE("/ca/:cn/certificates/:cert_cn", controllers.RevokeCertificate)
	v1.GET("/ca/:cn/certificates/:cert_cn", controllers.GetCertificatesCommonName)

	// Run the server
	err := router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
}
