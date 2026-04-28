package webui

import (
	"NetworkSetup/vlan"
	"net/http"

	"github.com/gin-gonic/gin"
)

func StartClientConsole(configPath string, listenAddr string) error {
	if _, _, err := vlan.EnsurePrivateKey(configPath); err != nil {
		return err
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.LoadHTMLGlob("webui/templates/*")
	autoOpenBrowser(listenAddr)

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "client.html", nil)
	})
	r.GET("/api/key", func(c *gin.Context) {
		info, err := getKeyInfo(configPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, info)
	})
	r.POST("/api/key/generate", func(c *gin.Context) {
		pub, err := vlan.GenerateAndWriteKeys(configPath, "")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, keyInfo{
			PublicKey:  pub,
			Generated:  true,
			HasPrivate: true,
		})
	})
	r.POST("/api/connect", func(c *gin.Context) {
		vlan.InitConfig(configPath, vlan.RunModeClient)
		started := vlan.StartManagedClient()
		c.JSON(http.StatusOK, gin.H{"started": started, "status": vlan.ManagedClientStatus()})
	})
	r.POST("/api/disconnect", func(c *gin.Context) {
		stopped := vlan.DisconnectManagedClient()
		c.JSON(http.StatusOK, gin.H{"disconnected": stopped, "status": vlan.ManagedClientStatus()})
	})
	r.GET("/api/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, vlan.ManagedClientStatus())
	})
	return r.Run(listenAddr)
}
