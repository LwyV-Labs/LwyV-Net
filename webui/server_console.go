package webui

import (
	"NetworkSetup/vlan"
	"net/http"

	"github.com/gin-gonic/gin"
)

func StartServerConsole(configPath string, listenAddr string) error {
	if _, _, err := vlan.EnsurePrivateKey(configPath); err != nil {
		return err
	}

	r := gin.Default()
	r.LoadHTMLGlob("webui/templates/*")
	autoOpenBrowser(listenAddr)

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "server.html", nil)
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
	r.POST("/api/start", func(c *gin.Context) {
		vlan.InitConfig(configPath, vlan.RunModeServer)
		started := vlan.StartManagedServer()
		c.JSON(http.StatusOK, gin.H{"started": started, "status": vlan.ManagedServerStatus()})
	})
	r.POST("/api/stop", func(c *gin.Context) {
		stopped := vlan.StopManagedServer()
		c.JSON(http.StatusOK, gin.H{"stopped": stopped, "status": vlan.ManagedServerStatus()})
	})
	r.GET("/api/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, vlan.ManagedServerStatus())
	})

	return r.Run(listenAddr)
}
