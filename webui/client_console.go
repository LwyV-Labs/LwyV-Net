package webui

import (
	"NetworkSetup/vlan"
	"net/http"

	"github.com/gin-gonic/gin"
)

func StartClientConsole(configPath string, listenAddr string) error {
	r := gin.Default()
	autoOpenBrowser(listenAddr)

	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(clientHTML))
	})
	r.GET("/api/config", func(c *gin.Context) {
		cfg, err := loadConfig(configPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg)
	})
	r.PUT("/api/config", func(c *gin.Context) {
		var cfg configPayload
		if err := c.ShouldBindJSON(&cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := saveConfig(configPath, cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
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

const clientHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>客户端控制台</title>
  <style>body{font-family:Arial;max-width:980px;margin:24px auto;} textarea{width:100%;height:340px;} button{margin-right:8px;}</style>
</head>
<body>
<h2>客户端 Web 控制台</h2>
<p id="status">状态加载中...</p>
<button onclick="loadConfig()">加载配置</button>
<button onclick="saveConfig()">保存配置</button>
<button onclick="connectVpn()">连接</button>
<button onclick="disconnectVpn()">断开</button>
<pre id="runtime"></pre>
<textarea id="cfg"></textarea>
<script>
async function loadConfig(){
  const res=await fetch('/api/config'); const data=await res.json();
  document.getElementById('cfg').value=JSON.stringify(data,null,2);
}
async function saveConfig(){
  const payload=JSON.parse(document.getElementById('cfg').value);
  const res=await fetch('/api/config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
  document.getElementById('status').innerText= res.ok?'配置保存成功':'配置保存失败';
}
async function connectVpn(){ await fetch('/api/connect',{method:'POST'}); await refreshStatus(); }
async function disconnectVpn(){ await fetch('/api/disconnect',{method:'POST'}); await refreshStatus(); }
async function refreshStatus(){
  const res=await fetch('/api/status'); const data=await res.json();
  document.getElementById('runtime').innerText=JSON.stringify(data,null,2);
  document.getElementById('status').innerText='运行中:'+data.running+' 连接中:'+data.connected+' 服务端:'+(data.serverIP||'');
}
setInterval(refreshStatus,2000); loadConfig(); refreshStatus();
</script>
</body>
</html>`
