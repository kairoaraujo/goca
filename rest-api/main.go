package main

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/kairoaraujo/goca/rest-api/controllers"
	_ "github.com/kairoaraujo/goca/rest-api/docs"
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

	router := gin.Default()
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := router.Group("/api")
	v1 := api.Group("/v1")

	// Routes
	v1.GET("/ca", controllers.GetCA)
	v1.POST("/ca", controllers.NewCA)
	v1.GET("/ca/:cn", controllers.GetCACommonName)
	v1.GET("/ca/:cn/certificates", controllers.GetCertificates)
	v1.GET("/ca/:cn/certificates/:cert_cn", controllers.GetCertificatesCommonName)

	// Run the server
	router.Run()
}
