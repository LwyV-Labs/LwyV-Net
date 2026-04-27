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
	autoOpenBrowser(listenAddr)
	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(serverHTML))
	})
	r.GET("/api/config", func(c *gin.Context) {
		cfg, err := loadConfig(configPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg)
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
		var req struct {
			PeerPublicKey string `json:"peerPublicKey"`
		}
		_ = c.ShouldBindJSON(&req)
		pub, err := vlan.GenerateAndWriteKeys(configPath, req.PeerPublicKey)
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
	r.POST("/api/start", func(c *gin.Context) {
		vlan.InitConfig(configPath, vlan.RunModeServer)
		started := vlan.StartManagedServer()
		c.JSON(http.StatusOK, gin.H{"started": started, "status": vlan.ManagedServerStatus()})
	})
	r.GET("/api/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, vlan.ManagedServerStatus())
	})
	return r.Run(listenAddr)
}

const serverHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>服务端控制台</title>
  <style>body{font-family:Arial;max-width:980px;margin:24px auto;} textarea{width:100%;height:320px;} button{margin-right:8px;}</style>
</head>
<body>
<h2>服务端 Web 控制台</h2>
<p id="status">状态加载中...</p>
<button onclick="loadConfig()">加载配置</button>
<button onclick="saveConfig()">保存配置</button>
<button onclick="loadKey()">查看公钥</button>
<button onclick="generateKey()">生成新密钥</button>
<button onclick="startServer()">启动服务端</button>
<h3>运行状态（在线用户数/连接信息）</h3>
<pre id="runtime"></pre>
<pre id="keyinfo"></pre>
<textarea id="cfg"></textarea>
<script>
async function loadConfig(){
  const res=await fetch('/api/config'); const data=await res.json();
  document.getElementById('cfg').value=JSON.stringify(data,null,2);
}
async function loadKey(){
  const res=await fetch('/api/key'); const data=await res.json();
  document.getElementById('keyinfo').innerText=JSON.stringify(data,null,2);
}
async function generateKey(){
  const peerPublicKey=prompt('可选：输入对端公钥（留空则不修改）','')||'';
  const res=await fetch('/api/key/generate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({peerPublicKey})});
  const data=await res.json();
  document.getElementById('keyinfo').innerText=JSON.stringify(data,null,2);
  await loadConfig();
}
async function saveConfig(){
  const payload=JSON.parse(document.getElementById('cfg').value);
  const res=await fetch('/api/config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
  document.getElementById('status').innerText=res.ok?'配置保存成功':'配置保存失败';
}
async function startServer(){ await fetch('/api/start',{method:'POST'}); await refreshStatus(); }
async function refreshStatus(){
  const res=await fetch('/api/status'); const data=await res.json();
  document.getElementById('runtime').innerText=JSON.stringify(data,null,2);
  document.getElementById('status').innerText='运行中:'+data.running+' 在线用户:'+(data.connectedNum||0);
}
setInterval(refreshStatus,2000); loadConfig(); loadKey(); refreshStatus();
</script>
</body>
</html>`
