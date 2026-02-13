package main

import (
	"crypto/md5"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	isBackingUp bool
	backupMutex sync.Mutex
)

func main() {
	// Get executable path and change to its directory
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exeDir := filepath.Dir(exePath)
	if err := os.Chdir(exeDir); err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("sqlite", "./blog.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Define command line flags for initialization
	initUser := flag.String("init-user", "", "Initial admin username")
	initPass := flag.String("init-pass", "", "Initial admin password")
	flag.Parse()

	// Handle standalone initialization if flags are provided
	if *initUser != "" && *initPass != "" {
		// Ensure typecho_users table exists
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS "typecho_users" (
			"uid" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"name" VARCHAR(32) UNIQUE,
			"password" VARCHAR(64),
			"mail" VARCHAR(150) UNIQUE,
			"url" VARCHAR(150),
			"screenName" VARCHAR(32),
			"created" INTEGER DEFAULT 0,
			"activated" INTEGER DEFAULT 0,
			"logged" INTEGER DEFAULT 0,
			"group" VARCHAR(16) DEFAULT 'visitor',
			"authCode" VARCHAR(64)
		)`)
		if err != nil {
			log.Fatal("Failed to create users table for initialization:", err)
		}

		now := time.Now().Unix()
		hash := hashTypecho(*initPass)
		_, err = db.Exec(`INSERT OR IGNORE INTO typecho_users (name, password, mail, screenName, "group", created, activated, logged) 
			VALUES (?, ?, ?, ?, 'administrator', ?, ?, ?)`,
			*initUser, hash, *initUser+"@example.com", "Administrator", now, now, now)
		if err != nil {
			log.Fatal("Failed to initialize admin user:", err)
		}
		log.Printf("Admin user '%s' initialized successfully.\n", *initUser)
		return
	}

	// Ensure sessions table exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS go_sessions (
		session_id TEXT PRIMARY KEY,
		username TEXT,
		created_at INTEGER
	)`)
	if err != nil {
		log.Fatal("Failed to create sessions table:", err)
	}

	// Ensure options table exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS go_options (
		name TEXT PRIMARY KEY,
		value TEXT
	)`)
	if err != nil {
		log.Fatal("Failed to create options table:", err)
	}

	// Ensure category settings table exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS go_category_settings (
		mid INTEGER PRIMARY KEY,
		show_on_home INTEGER DEFAULT 1,
		is_offline INTEGER DEFAULT 0
	)`)
	if err != nil {
		log.Fatal("Failed to create category settings table:", err)
	}

	adminPath := getOption(db, "adminPath", "admin")
	if !strings.HasPrefix(adminPath, "/") {
		adminPath = "/" + adminPath
	}
	adminPath = strings.TrimSuffix(adminPath, "/")

	r := gin.Default()
	r.SetTrustedProxies(nil)
	r.SetFuncMap(template.FuncMap{
		"now": func() time.Time { return time.Now() },
		"substring": func(s string, l int) string {
			runes := []rune(s)
			if len(runes) > l {
				return string(runes[:l]) + "..."
			}
			return s
		},
		"adminPath": func() string { return adminPath },
		// 分页辅助函数
		"iterate": func(start, end int) []int {
			var result []int
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
			return result
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		// 计算分页范围：返回当前页附近应该显示的页码
		"pageRange": func(current, total int) []int {
			var result []int
			// 计算显示范围：当前页 ± 2
			start := current - 2
			end := current + 2
			// 确保不超出边界
			if start < 2 {
				start = 2
			}
			if end > total-1 {
				end = total - 1
			}
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
			return result
		},
	})
	r.LoadHTMLGlob("templates/admin/*")

	// Middleware for simple cookie auth
	authMiddleware := func(c *gin.Context) {
		sessionID, err := c.Cookie("te_auth")
		if err != nil {
			c.Redirect(http.StatusFound, adminPath+"/login")
			c.Abort()
			return
		}

		var username string
		var createdAt int64
		err = db.QueryRow("SELECT username, created_at FROM go_sessions WHERE session_id = ?", sessionID).Scan(&username, &createdAt)

		timeout := int64(getOptionInt(db, "sessionTimeout", 30)) * 60
		if err != nil || time.Now().Unix()-createdAt > timeout {
			if err == nil {
				db.Exec("DELETE FROM go_sessions WHERE session_id = ?", sessionID)
			}
			c.SetCookie("te_auth", "", -1, "/", "", false, true)
			c.Redirect(http.StatusFound, adminPath+"/login")
			c.Abort()
			return
		}

		// Update activity time (sliding window)
		db.Exec("UPDATE go_sessions SET created_at = ? WHERE session_id = ?", time.Now().Unix(), sessionID)
		c.SetCookie("te_auth", sessionID, int(timeout), "/", "", false, true)

		// Fetch user group
		var userGroup string
		db.QueryRow("SELECT \"group\" FROM typecho_users WHERE name = ?", username).Scan(&userGroup)

		c.Set("username", username)
		c.Set("userGroup", userGroup)
		c.Set("adminPath", adminPath)
		c.Next()
	}

	// Middleware to prevent write operations for visitors (applied to specific routes)
	writeProtectMiddleware := func(c *gin.Context) {
		group, _ := c.Get("userGroup")
		if group == "visitor" {
			log.Printf("访问拦截: 用户[%s] 角色[%s] 尝试执行写操作: %s", c.MustGet("username"), group, c.Request.URL.Path)
			// 优化判断逻辑：如果是 API 常用路径或 headers 匹配，则返回 JSON
			if c.GetHeader("X-Requested-With") == "XMLHttpRequest" ||
				strings.Contains(c.GetHeader("Accept"), "application/json") ||
				strings.HasSuffix(c.Request.URL.Path, "/restart") ||
				strings.HasSuffix(c.Request.URL.Path, "/toggle") {
				c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "访客模式：无权进行此操作"})
			} else {
				c.HTML(http.StatusForbidden, "admin_error.html", gin.H{
					"AdminPath":    adminPath,
					"ErrorTitle":   "操作受限",
					"ErrorMessage": "您当前处于访客模式，无权执行修改操作。",
				})
			}
			c.Abort()
			return
		}
		c.Next()
	}

	r.GET(adminPath+"/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin_login.html", gin.H{"AdminPath": adminPath})
	})

	r.POST(adminPath+"/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		var storedHash string
		err := db.QueryRow("SELECT password FROM typecho_users WHERE name=?", username).Scan(&storedHash)

		if err == nil && checkTypechoHash(password, storedHash) {
			timeout := getOptionInt(db, "sessionTimeout", 30) * 60
			// Cleanup old sessions
			db.Exec("DELETE FROM go_sessions WHERE created_at < ?", time.Now().Unix()-int64(timeout))

			// 更新最后登录时间
			db.Exec("UPDATE typecho_users SET logged = ? WHERE name = ?", time.Now().Unix(), username)

			sessionID := uuid.New().String()
			_, err = db.Exec("INSERT INTO go_sessions (session_id, username, created_at) VALUES (?, ?, ?)",
				sessionID, username, time.Now().Unix())
			if err != nil {
				c.HTML(http.StatusInternalServerError, "admin_error.html", gin.H{
					"AdminPath":    adminPath,
					"ErrorTitle":   "登录失败",
					"ErrorMessage": "创建会话时出现错误，请重新尝试登录。",
				})
				return
			}
			c.SetCookie("te_auth", sessionID, timeout, "/", "", false, true)
			c.Redirect(http.StatusFound, adminPath+"/dashboard")
		} else {
			c.HTML(http.StatusUnauthorized, "admin_error.html", gin.H{
				"AdminPath":    adminPath,
				"ErrorTitle":   "登录失败",
				"ErrorMessage": "用户名或密码错误，请重新输入。",
			})
		}
	})

	r.GET(adminPath, func(c *gin.Context) {
		c.Redirect(http.StatusFound, adminPath+"/dashboard")
	})

	admin := r.Group(adminPath, authMiddleware)

	admin.GET("/dashboard", func(c *gin.Context) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")
		group, _ := c.Get("userGroup")

		// 基础统计
		var postCount, commentCount, categoryCount, attachmentCount int
		var weekPostCount, weekCommentCount int
		now := time.Now()

		// 计算周一 00:00:00 (以周一为一周起始)
		daysSinceMonday := int(now.Weekday()) - 1
		if daysSinceMonday < 0 {
			daysSinceMonday = 6 // 周日变成 6
		}
		weekStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -daysSinceMonday).Unix()

		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='post'").Scan(&postCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments").Scan(&commentCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_metas WHERE type='category'").Scan(&categoryCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='attachment'").Scan(&attachmentCount)

		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='post' AND created >= ?", weekStart).Scan(&weekPostCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments WHERE created >= ?", weekStart).Scan(&weekCommentCount)

		// 流量统计
		todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
		var todayPV, todayHumanIP, todayBotIP, todayBotPV, totalHumanPV, totalHumanIP, totalBotPV, totalBotIP int
		db.QueryRow("SELECT COUNT(*) FROM go_stats_logs WHERE created >= ? AND is_bot=0", todayStart).Scan(&todayPV)
		db.QueryRow("SELECT COUNT(DISTINCT ip) FROM go_stats_logs WHERE created >= ? AND is_bot=0", todayStart).Scan(&todayHumanIP)
		db.QueryRow("SELECT COUNT(DISTINCT ip) FROM go_stats_logs WHERE created >= ? AND is_bot=1", todayStart).Scan(&todayBotIP)
		db.QueryRow("SELECT COUNT(*) FROM go_stats_logs WHERE created >= ? AND is_bot=1", todayStart).Scan(&todayBotPV)
		db.QueryRow("SELECT COUNT(*) FROM go_stats_logs WHERE is_bot=0").Scan(&totalHumanPV)
		db.QueryRow("SELECT COUNT(DISTINCT ip) FROM go_stats_logs WHERE is_bot=0").Scan(&totalHumanIP)
		db.QueryRow("SELECT COUNT(*) FROM go_stats_logs WHERE is_bot=1").Scan(&totalBotPV)
		db.QueryRow("SELECT COUNT(DISTINCT ip) FROM go_stats_logs WHERE is_bot=1").Scan(&totalBotIP)

		// 获取日志保留天数设置，用于前端标签展示
		retentionStr := getOption(db, "logRetentionDays", "30")
		retentionLabel := retentionStr + "天内"
		if retentionStr == "0" {
			retentionLabel = "历史累计"
		}

		// 数据库大小
		dbFile, _ := os.Stat("blog.sqlite")
		dbSize := "0 MB"
		if dbFile != nil {
			dbSize = fmt.Sprintf("%.2f MB", float64(dbFile.Size())/(1024*1024))
		}

		// 系统信息
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memUsed := fmt.Sprintf("%.2f MB", float64(m.Alloc)/(1024*1024))

		var totalMem int
		var si syscall.Sysinfo_t
		if err := syscall.Sysinfo(&si); err == nil {
			// 将字节转换为 GB，并取整（向上取整以补偿内核占用空间）
			ramBytes := float64(si.Totalram) * float64(si.Unit)
			totalMem = int((ramBytes + (512 * 1024 * 1024)) / (1024 * 1024 * 1024))
		}

		// 目录占用统计函数
		getDirSize := func(path string) float64 {
			var size int64
			filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					size += info.Size()
				}
				return nil
			})
			return float64(size) / (1024 * 1024)
		}

		// 剩余磁盘空间 (/)
		var diskFree string
		var fs syscall.Statfs_t
		if err := syscall.Statfs("/", &fs); err == nil {
			free := float64(fs.Bavail*uint64(fs.Bsize)) / (1024 * 1024 * 1024)
			total := float64(fs.Blocks*uint64(fs.Bsize)) / (1024 * 1024 * 1024)
			diskFree = fmt.Sprintf("%.1f GB 可用 / %.1f GB 总计", free, total)
		} else {
			diskFree = "获取失败"
		}

		// 系统负载
		var sysLoad string
		if loadData, err := os.ReadFile("/proc/loadavg"); err == nil {
			parts := strings.Fields(string(loadData))
			if len(parts) >= 3 {
				sysLoad = fmt.Sprintf("%s / %s / %s (1/5/15 min)", parts[0], parts[1], parts[2])
			} else {
				sysLoad = "解析失败"
			}
		} else {
			sysLoad = "不支持 (Linux)"
		}

		c.HTML(http.StatusOK, "admin_dashboard.html", gin.H{
			"Username":         username,
			"UserGroup":        group,
			"Tab":              "dashboard",
			"AdminPath":        adminPath,
			"PostCount":        postCount,
			"CommentCount":     commentCount,
			"WeekPostCount":    weekPostCount,
			"WeekCommentCount": weekCommentCount,
			"CategoryCount":    categoryCount,
			"AttachmentCount":  attachmentCount,
			"TodayPV":          todayPV,
			"TodayIP":          todayHumanIP,
			"TodayBotIP":       todayBotIP,
			"TotalPV":          totalHumanPV,
			"TotalIP":          totalHumanIP,
			"TodayBotPV":       todayBotPV,
			"TotalBotPV":       totalBotPV,
			"TotalBotIP":       totalBotIP,
			"RetentionLabel":   retentionLabel,
			"DbSize":           dbSize,
			"MemUsed":          memUsed,
			"GoVersion":        runtime.Version(),
			"OS":               runtime.GOOS,
			"Arch":             runtime.GOARCH,
			"CPUs":             runtime.NumCPU(),
			"TotalMem":         totalMem,
			"UploadSize":       fmt.Sprintf("%.2f MB", getDirSize("usr/uploads")),
			"BackupSize":       fmt.Sprintf("%.2f MB", getDirSize("backups")),
			"DiskFree":         diskFree,
			"SysLoad":          sysLoad,
		})
	})

	admin.GET("/logout", func(c *gin.Context) {
		sessionID, _ := c.Cookie("te_auth")
		if sessionID != "" {
			db.Exec("DELETE FROM go_sessions WHERE session_id = ?", sessionID)
		}
		c.SetCookie("te_auth", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, adminPath+"/login")
	})

	admin.GET("/profile", func(c *gin.Context) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")
		c.HTML(http.StatusOK, "admin_profile.html", gin.H{
			"Username":  username,
			"Tab":       "profile",
			"AdminPath": adminPath,
		})
	})

	admin.POST("/profile", writeProtectMiddleware, func(c *gin.Context) {
		username, _ := c.Get("username")
		oldPassword := c.PostForm("old_password")
		newPassword := c.PostForm("new_password")
		confirmPassword := c.PostForm("confirm_password")

		if newPassword != confirmPassword {
			c.HTML(http.StatusOK, "admin_profile.html", gin.H{
				"Username":     username,
				"Tab":          "profile",
				"AdminPath":    adminPath,
				"ErrorMessage": "两次输入的新密码不一致",
			})
			return
		}

		var storedHash string
		err := db.QueryRow("SELECT password FROM typecho_users WHERE name=?", username).Scan(&storedHash)
		if err != nil || !checkTypechoHash(oldPassword, storedHash) {
			c.HTML(http.StatusOK, "admin_profile.html", gin.H{
				"Username":     username,
				"Tab":          "profile",
				"AdminPath":    adminPath,
				"ErrorMessage": "旧密码错误",
			})
			return
		}

		newHash := hashTypecho(newPassword)
		_, err = db.Exec("UPDATE typecho_users SET password=? WHERE name=?", newHash, username)
		if err != nil {
			c.HTML(http.StatusOK, "admin_profile.html", gin.H{
				"Username":     username,
				"Tab":          "profile",
				"AdminPath":    adminPath,
				"ErrorMessage": "数据库更新失败",
			})
			return
		}

		c.HTML(http.StatusOK, "admin_profile.html", gin.H{
			"Username":       username,
			"Tab":            "profile",
			"AdminPath":      adminPath,
			"SuccessMessage": "密码修改成功",
		})
	})

	admin.GET("/settings", func(c *gin.Context) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")

		var categories []map[string]interface{}
		rows, _ := db.Query("SELECT mid, name FROM typecho_metas WHERE type='category' ORDER BY \"order\" ASC, mid ASC")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var mid int
				var name string
				rows.Scan(&mid, &name)
				categories = append(categories, map[string]interface{}{
					"Mid":  mid,
					"Name": name,
				})
			}
		}

		group, _ := c.Get("userGroup")
		apiKey := getOption(db, "grokApiKey", "")
		if group == "visitor" && apiKey != "" {
			apiKey = "********************************"
		}

		c.HTML(http.StatusOK, "admin_settings.html", gin.H{
			"Username":           username,
			"Tab":                "settings",
			"AdminPath":          adminPath,
			"SiteTitle":          getOption(db, "title", "我的博客"),
			"SiteDescription":    getOption(db, "description", "基于 Go 语言的极速博客系统"),
			"SiteUrl":            getOption(db, "siteUrl", "http://localhost:8190"),
			"ConfigAdminPath":    getOption(db, "adminPath", "admin"),
			"AiThreshold":        getOption(db, "aiThreshold", "5"),
			"SessionTimeout":     getOption(db, "sessionTimeout", "30"),
			"SiteKeywords":       getOption(db, "keywords", ""),
			"FooterCode":         getOption(db, "footerCode", ""),
			"PageSize":           getOption(db, "pageSize", "10"),
			"RecentPostsSize":    getOption(db, "recentPostsSize", "15"),
			"RecentCommentsSize": getOption(db, "recentCommentsSize", "10"),
			"GrokApiKey":         apiKey,
			"AiApiUrl":           getOption(db, "aiApiUrl", "https://api.groq.com/openai/v1/chat/completions"),
			"AiModel":            getOption(db, "aiModel", "llama-3.3-70b-versatile"),
			"DefaultCategory":    getOption(db, "defaultCategory", "1"),
			"CommentAudit":       getOption(db, "commentAudit", "0"),
			"StatsBufferSize":    getOption(db, "statsBufferSize", "100"),
			"LogRetentionDays":   getOption(db, "logRetentionDays", "30"),
			"CommentLimitIP":     getOption(db, "commentLimitIP", "1"),
			"CommentLimitGlobal": getOption(db, "commentLimitGlobal", "2"),
			"CommentsEnabled":    getOption(db, "commentsEnabled", "1"),
			"AllCategories":      categories,
		})
	})

	admin.POST("/settings", writeProtectMiddleware, func(c *gin.Context) {
		username, _ := c.Get("username")
		curAdminPath, _ := c.Get("adminPath")
		title := c.PostForm("title")
		description := c.PostForm("description")
		pageSize := c.PostForm("pageSize")
		recentPostsSize := c.PostForm("recentPostsSize")
		recentCommentsSize := c.PostForm("recentCommentsSize")
		grokApiKey := c.PostForm("grokApiKey")
		aiApiUrl := c.PostForm("aiApiUrl")
		aiModel := c.PostForm("aiModel")
		aiThreshold := c.PostForm("aiThreshold")
		sessionTimeout := c.PostForm("sessionTimeout")
		keywords := c.PostForm("keywords")
		footerCode := c.PostForm("footerCode")
		defaultCategory := c.PostForm("defaultCategory")
		siteUrl := c.PostForm("siteUrl")
		newAdminPath := c.PostForm("adminPath")
		commentAudit := c.DefaultPostForm("commentAudit", "0")
		statsBufferSize := c.PostForm("statsBufferSize")
		logRetentionDays := c.PostForm("logRetentionDays")
		commentLimitIP := c.PostForm("commentLimitIP")
		commentLimitGlobal := c.PostForm("commentLimitGlobal")
		commentsEnabled := c.DefaultPostForm("commentsEnabled", "0")

		setOption(db, "title", title)
		setOption(db, "description", description)
		setOption(db, "siteUrl", siteUrl)
		oldAdminPath := getOption(db, "adminPath", "admin")
		setOption(db, "adminPath", newAdminPath)
		setOption(db, "pageSize", pageSize)
		setOption(db, "recentPostsSize", recentPostsSize)
		setOption(db, "recentCommentsSize", recentCommentsSize)
		setOption(db, "grokApiKey", grokApiKey)
		setOption(db, "aiApiUrl", aiApiUrl)
		setOption(db, "aiModel", aiModel)
		setOption(db, "aiThreshold", aiThreshold)
		setOption(db, "sessionTimeout", sessionTimeout)
		setOption(db, "keywords", keywords)
		setOption(db, "footerCode", footerCode)
		setOption(db, "defaultCategory", defaultCategory)
		setOption(db, "commentAudit", commentAudit)
		setOption(db, "statsBufferSize", statsBufferSize)
		setOption(db, "logRetentionDays", logRetentionDays)
		setOption(db, "commentLimitIP", commentLimitIP)
		setOption(db, "commentLimitGlobal", commentLimitGlobal)
		setOption(db, "commentsEnabled", commentsEnabled)

		successMsg := "设置保存成功"
		if oldAdminPath != newAdminPath {
			successMsg = "设置保存成功，后台路径已更新（重启后生效）"
		}

		var categories []map[string]interface{}
		rows, _ := db.Query("SELECT mid, name FROM typecho_metas WHERE type='category' ORDER BY \"order\" ASC, mid ASC")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var mid int
				var name string
				rows.Scan(&mid, &name)
				categories = append(categories, map[string]interface{}{
					"Mid":  mid,
					"Name": name,
				})
			}
		}

		c.HTML(http.StatusOK, "admin_settings.html", gin.H{
			"Username":           username,
			"Tab":                "settings",
			"AdminPath":          curAdminPath,
			"SiteTitle":          title,
			"SiteDescription":    description,
			"PageSize":           pageSize,
			"RecentPostsSize":    recentPostsSize,
			"RecentCommentsSize": recentCommentsSize,
			"GrokApiKey":         grokApiKey,
			"AiApiUrl":           aiApiUrl,
			"AiModel":            aiModel,
			"AiThreshold":        aiThreshold,
			"SessionTimeout":     sessionTimeout,
			"SiteKeywords":       keywords,
			"FooterCode":         footerCode,
			"DefaultCategory":    defaultCategory,
			"SiteUrl":            siteUrl,
			"ConfigAdminPath":    newAdminPath,
			"CommentAudit":       commentAudit,
			"StatsBufferSize":    statsBufferSize,
			"LogRetentionDays":   logRetentionDays,
			"CommentLimitIP":     commentLimitIP,
			"CommentLimitGlobal": commentLimitGlobal,
			"CommentsEnabled":    commentsEnabled,
			"AllCategories":      categories,
			"SuccessMessage":     successMsg,
		})
	})

	admin.GET("/posts", func(c *gin.Context) {
		pageStr := c.DefaultQuery("page", "1")
		page := 1
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := 20
		offset := (page - 1) * pageSize

		group, _ := c.Get("userGroup")
		var total int
		var rows *sql.Rows
		var err error

		stickyCidsStr := getOption(db, "sticky_cids", "")
		stickyMap := make(map[int]bool)
		if stickyCidsStr != "" {
			for _, s := range strings.Split(stickyCidsStr, ",") {
				var id int
				fmt.Sscan(s, &id)
				if id > 0 {
					stickyMap[id] = true
				}
			}
		}

		orderBy := "created DESC"
		if stickyCidsStr != "" {
			// 基础校验，确保仅包含数字和逗号
			isSafe := true
			for _, r := range stickyCidsStr {
				if (r < '0' || r > '9') && r != ',' {
					isSafe = false
					break
				}
			}
			if isSafe {
				orderBy = fmt.Sprintf("CASE WHEN cid IN (%s) THEN 1 ELSE 0 END DESC, created DESC", stickyCidsStr)
			}
		}

		if group == "visitor" {
			db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='post' AND status='publish'").Scan(&total)
			rows, err = db.Query("SELECT cid, title, created, status FROM typecho_contents WHERE type='post' AND status='publish' ORDER BY "+orderBy+" LIMIT ? OFFSET ?", pageSize, offset)
		} else {
			db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='post'").Scan(&total)
			rows, err = db.Query("SELECT cid, title, created, status FROM typecho_contents WHERE type='post' ORDER BY "+orderBy+" LIMIT ? OFFSET ?", pageSize, offset)
		}

		if err != nil {
			c.String(500, err.Error())
			return
		}
		defer rows.Close()

		var posts []map[string]interface{}
		for rows.Next() {
			var cid int
			var title, status string
			var created int64
			rows.Scan(&cid, &title, &created, &status)
			posts = append(posts, map[string]interface{}{
				"Cid":     cid,
				"Title":   title,
				"Status":  status,
				"Created": time.Unix(created, 0).Format("2006-01-02"),
				"IsTop":   stickyMap[cid],
			})
		}

		totalPages := (total + pageSize - 1) / pageSize
		username, _ := c.Get("username")
		c.HTML(http.StatusOK, "admin_posts.html", gin.H{
			"Username":    username,
			"UserGroup":   group,
			"Posts":       posts,
			"Tab":         "posts",
			"CurrentPage": page,
			"TotalPages":  totalPages,
			"HasPrev":     page > 1,
			"HasNext":     page < totalPages,
			"PrevPage":    page - 1,
			"NextPage":    page + 1,
		})
	})

	// Comment Management with Pagination
	admin.GET("/comments", func(c *gin.Context) {
		pageStr := c.DefaultQuery("page", "1")
		page := 1
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := 20
		offset := (page - 1) * pageSize

		var total int
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments").Scan(&total)

		rows, err := db.Query("SELECT coid, cid, author, text, status, created FROM typecho_comments ORDER BY created DESC LIMIT ? OFFSET ?", pageSize, offset)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		defer rows.Close()

		var comments []map[string]interface{}
		for rows.Next() {
			var coid, cid int
			var author, text, status string
			var created int64
			rows.Scan(&coid, &cid, &author, &text, &status, &created)
			comments = append(comments, map[string]interface{}{
				"Coid":    coid,
				"Cid":     cid,
				"Author":  author,
				"Text":    text,
				"Status":  status,
				"Created": time.Unix(created, 0).Format("2006-01-02 15:04"),
			})
		}

		totalPages := (total + pageSize - 1) / pageSize
		username, _ := c.Get("username")
		c.HTML(http.StatusOK, "admin_comments.html", gin.H{
			"Username":    username,
			"Comments":    comments,
			"Tab":         "comments",
			"CurrentPage": page,
			"TotalPages":  totalPages,
			"HasPrev":     page > 1,
			"HasNext":     page < totalPages,
			"PrevPage":    page - 1,
			"NextPage":    page + 1,
		})
	})

	admin.POST("/comment/toggle/:coid", writeProtectMiddleware, func(c *gin.Context) {
		coid := c.Param("coid")
		var currentStatus string
		err := db.QueryRow("SELECT status FROM typecho_comments WHERE coid=?", coid).Scan(&currentStatus)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "评论不存在"})
			return
		}

		newStatus := "approved"
		if currentStatus == "approved" {
			newStatus = "waiting"
		}

		_, err = db.Exec("UPDATE typecho_comments SET status=? WHERE coid=?", newStatus, coid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
			return
		}

		// Update commentsNum in contents table
		if newStatus == "approved" {
			db.Exec("UPDATE typecho_contents SET commentsNum = commentsNum + 1 WHERE cid = (SELECT cid FROM typecho_comments WHERE coid = ?)", coid)
		} else {
			db.Exec("UPDATE typecho_contents SET commentsNum = commentsNum - 1 WHERE cid = (SELECT cid FROM typecho_comments WHERE coid = ?)", coid)
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "newStatus": newStatus})
	})

	admin.POST("/comment/approve/:coid", writeProtectMiddleware, func(c *gin.Context) {
		coid := c.Param("coid")
		db.Exec("UPDATE typecho_comments SET status='approved' WHERE coid=?", coid)
		c.Redirect(http.StatusFound, ""+adminPath+"/comments")
	})

	admin.POST("/comment/delete/:coid", writeProtectMiddleware, func(c *gin.Context) {
		coid := c.Param("coid")
		var cid int
		db.QueryRow("SELECT cid FROM typecho_comments WHERE coid=?", coid).Scan(&cid)
		db.Exec("DELETE FROM typecho_comments WHERE coid=?", coid)
		db.Exec("UPDATE typecho_contents SET commentsNum = MAX(0, commentsNum - 1) WHERE cid=?", cid)
		c.Redirect(http.StatusFound, ""+adminPath+"/comments")
	})

	admin.POST("/post/delete/:cid", writeProtectMiddleware, func(c *gin.Context) {
		cid := c.Param("cid")

		// 物理删除文章关联的附件文件
		rows, err := db.Query("SELECT title FROM typecho_contents WHERE parent=? AND type='attachment'", cid)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var relPath string
				if err := rows.Scan(&relPath); err == nil && relPath != "" {
					// 转换路径并物理删除：/blog/usr/uploads/... -> ./usr/uploads/...
					localSubPath := strings.TrimPrefix(relPath, "/blog/")
					// 安全校验：仅允许物理删除以 usr/uploads/ 开头的路径，且禁止路径穿越 (..)
					if strings.HasPrefix(localSubPath, "usr/uploads/") && !strings.Contains(localSubPath, "..") {
						absPath := filepath.Join(".", localSubPath)
						os.Remove(absPath)
					}
				}
			}
		}

		// Delete the post
		db.Exec("DELETE FROM typecho_contents WHERE cid=?", cid)
		// Delete relationships (categories/tags)
		db.Exec("DELETE FROM typecho_relationships WHERE cid=?", cid)
		// Delete associated comments
		db.Exec("DELETE FROM typecho_comments WHERE cid=?", cid)
		// Delete associated attachments
		db.Exec("DELETE FROM typecho_contents WHERE parent=? AND type='attachment'", cid)

		c.Redirect(http.StatusFound, ""+adminPath+"/posts")
	})

	// Category Management
	admin.GET("/categories", func(c *gin.Context) {
		pageStr := c.DefaultQuery("page", "1")
		page := 1
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := 20
		offset := (page - 1) * pageSize

		var total int
		db.QueryRow("SELECT COUNT(*) FROM typecho_metas WHERE type='category'").Scan(&total)

		rows, err := db.Query(`SELECT m.mid, m.name, m.slug, 
                               (SELECT COUNT(*) FROM typecho_relationships r 
                                JOIN typecho_contents c ON r.cid = c.cid 
                                WHERE r.mid = m.mid AND c.type='post' AND c.status='publish') as count, 
                                 m."order", COALESCE(s.show_on_home, 1), COALESCE(s.is_offline, 0) 
                                 FROM typecho_metas m 
                                 LEFT JOIN go_category_settings s ON m.mid = s.mid 
                                 WHERE m.type='category' ORDER BY m."order" ASC, m.mid ASC LIMIT ? OFFSET ?`, pageSize, offset)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		defer rows.Close()

		var categories []map[string]interface{}
		for rows.Next() {
			var mid, count, order, showOnHome, isOffline int
			var name, slug string
			rows.Scan(&mid, &name, &slug, &count, &order, &showOnHome, &isOffline)
			categories = append(categories, map[string]interface{}{
				"Mid":        mid,
				"Name":       name,
				"Slug":       slug,
				"Count":      count,
				"Order":      order,
				"ShowOnHome": showOnHome == 1,
				"IsOffline":  isOffline == 1,
			})
		}

		totalPages := (total + pageSize - 1) / pageSize
		username, _ := c.Get("username")
		c.HTML(http.StatusOK, "admin_categories.html", gin.H{
			"Username":    username,
			"Categories":  categories,
			"Tab":         "categories",
			"CurrentPage": page,
			"TotalPages":  totalPages,
			"HasPrev":     page > 1,
			"HasNext":     page < totalPages,
			"PrevPage":    page - 1,
			"NextPage":    page + 1,
		})
	})

	admin.POST("/category/save", writeProtectMiddleware, func(c *gin.Context) {
		name := c.PostForm("name")
		slug := c.PostForm("slug")
		midStr := c.PostForm("mid")
		order := c.DefaultPostForm("order", "0")
		showOnHome := c.DefaultPostForm("showOnHome", "0")
		isOffline := c.DefaultPostForm("isOffline", "0")

		if midStr == "" || midStr == "0" {
			res, err := db.Exec("INSERT INTO typecho_metas (name, slug, type, description, count, \"order\", parent) VALUES (?, ?, 'category', '', 0, ?, 0)", name, slug, order)
			if err != nil {
				c.String(500, err.Error())
				return
			}
			lastId, _ := res.LastInsertId()
			db.Exec("INSERT INTO go_category_settings (mid, show_on_home, is_offline) VALUES (?, ?, ?)", lastId, showOnHome, isOffline)
		} else {
			_, err := db.Exec("UPDATE typecho_metas SET name=?, slug=?, \"order\"=? WHERE mid=?", name, slug, order, midStr)
			if err != nil {
				c.String(500, err.Error())
				return
			}
			db.Exec("INSERT INTO go_category_settings (mid, show_on_home, is_offline) VALUES (?, ?, ?) ON CONFLICT(mid) DO UPDATE SET show_on_home=excluded.show_on_home, is_offline=excluded.is_offline", midStr, showOnHome, isOffline)
		}
		c.Redirect(http.StatusFound, ""+adminPath+"/categories")
	})

	admin.POST("/category/reorder", writeProtectMiddleware, func(c *gin.Context) {
		var reorderReq struct {
			Orders []struct {
				Mid   int `json:"mid"`
				Order int `json:"order"`
			} `json:"orders"`
		}

		if err := c.ShouldBindJSON(&reorderReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "无效的请求参数"})
			return
		}

		tx, err := db.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "数据库开启事务失败"})
			return
		}

		stmt, err := tx.Prepare("UPDATE typecho_metas SET \"order\"=? WHERE mid=?")
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "预处理语句失败"})
			return
		}
		defer stmt.Close()

		for _, item := range reorderReq.Orders {
			_, err := stmt.Exec(item.Order, item.Mid)
			if err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "更新排序失败"})
				return
			}
		}

		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "提交事务失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// User Management
	admin.GET("/users", func(c *gin.Context) {
		username, _ := c.Get("username")
		group, _ := c.Get("userGroup")

		var rows *sql.Rows
		var err error
		if group == "visitor" {
			rows, err = db.Query("SELECT uid, name, screenName, mail, url, \"group\", logged FROM typecho_users WHERE name=? ORDER BY uid ASC", username)
		} else {
			rows, err = db.Query("SELECT uid, name, screenName, mail, url, \"group\", logged FROM typecho_users ORDER BY uid ASC")
		}

		if err != nil {
			c.String(500, err.Error())
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var uid uint64
			var logged int64
			var name, screenName, mail, url, group string
			rows.Scan(&uid, &name, &screenName, &mail, &url, &group, &logged)

			loggedStr := ""
			if logged > 0 {
				loggedStr = time.Unix(logged, 0).Format("2006-01-02 15:04")
			}

			users = append(users, map[string]interface{}{
				"Uid":        uid,
				"Name":       name,
				"ScreenName": screenName,
				"Mail":       mail,
				"Url":        url,
				"Group":      group,
				"Logged":     loggedStr,
			})
		}

		c.HTML(http.StatusOK, "admin_users.html", gin.H{
			"Username":  username,
			"UserGroup": group,
			"Tab":       "users",
			"AdminPath": adminPath,
			"Users":     users,
		})
	})

	admin.GET("/user/add", func(c *gin.Context) {
		username, _ := c.Get("username")
		group, _ := c.Get("userGroup")
		c.HTML(http.StatusOK, "admin_user_edit.html", gin.H{
			"Username":  username,
			"UserGroup": group,
			"Tab":       "users",
			"AdminPath": adminPath,
			"User":      map[string]interface{}{},
		})
	})

	admin.POST("/user/add", writeProtectMiddleware, func(c *gin.Context) {
		username, _ := c.Get("username")
		name := c.PostForm("name")
		screenName := c.PostForm("screenName")
		mail := c.PostForm("mail")
		password := c.PostForm("password")
		url := c.PostForm("url")
		group := c.PostForm("group")

		// Check if user exists
		var exists int
		db.QueryRow("SELECT COUNT(*) FROM typecho_users WHERE name=?", name).Scan(&exists)
		if exists > 0 {
			c.HTML(http.StatusOK, "admin_user_edit.html", gin.H{
				"Username":     username,
				"Tab":          "users",
				"AdminPath":    adminPath,
				"ErrorMessage": "用户名已存在",
				"User": map[string]interface{}{
					"Name":       name,
					"ScreenName": screenName,
					"Mail":       mail,
					"Url":        url,
					"Group":      group,
				},
			})
			return
		}

		hash := hashTypecho(password)
		now := time.Now().Unix()
		_, err := db.Exec(`INSERT INTO typecho_users (name, password, mail, url, screenName, created, activated, logged, "group") 
			VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
			name, hash, mail, url, screenName, now, now, group)

		if err != nil {
			c.HTML(http.StatusOK, "admin_user_edit.html", gin.H{
				"Username":     username,
				"Tab":          "users",
				"AdminPath":    adminPath,
				"ErrorMessage": "插入数据库失败: " + err.Error(),
				"User": map[string]interface{}{
					"Name":       name,
					"ScreenName": screenName,
					"Mail":       mail,
					"Url":        url,
					"Group":      group,
				},
			})
			return
		}

		c.Redirect(http.StatusFound, adminPath+"/users")
	})

	admin.GET("/user/edit/:uid", func(c *gin.Context) {
		uid := c.Param("uid")
		username, _ := c.Get("username")

		var u map[string]interface{} = make(map[string]interface{})
		var name, screenName, mail, url, group string
		err := db.QueryRow("SELECT name, screenName, mail, url, \"group\" FROM typecho_users WHERE uid=?", uid).
			Scan(&name, &screenName, &mail, &url, &group)

		if err != nil {
			c.String(404, "User not found")
			return
		}

		u["Uid"] = uid
		u["Name"] = name
		u["ScreenName"] = screenName
		u["Mail"] = mail
		u["Url"] = url
		u["Group"] = group

		groupCurrent, _ := c.Get("userGroup")
		if groupCurrent == "visitor" && name != username {
			c.HTML(http.StatusForbidden, "admin_error.html", gin.H{
				"AdminPath":    adminPath,
				"ErrorTitle":   "横向越权拦截",
				"ErrorMessage": "访客模式下只能编辑自己的资料。",
			})
			return
		}

		c.HTML(http.StatusOK, "admin_user_edit.html", gin.H{
			"Username":  username,
			"UserGroup": groupCurrent,
			"Tab":       "users",
			"AdminPath": adminPath,
			"User":      u,
		})
	})

	admin.POST("/user/edit/:uid", writeProtectMiddleware, func(c *gin.Context) {
		uid := c.Param("uid")
		screenName := c.PostForm("screenName")
		mail := c.PostForm("mail")
		password := c.PostForm("password")
		url := c.PostForm("url")
		group := c.PostForm("group")

		if password != "" {
			hash := hashTypecho(password)
			_, err := db.Exec("UPDATE typecho_users SET screenName=?, mail=?, password=?, url=?, \"group\"=? WHERE uid=?",
				screenName, mail, hash, url, group, uid)
			if err != nil {
				c.String(500, err.Error())
				return
			}
		} else {
			_, err := db.Exec("UPDATE typecho_users SET screenName=?, mail=?, url=?, \"group\"=? WHERE uid=?",
				screenName, mail, url, group, uid)
			if err != nil {
				c.String(500, err.Error())
				return
			}
		}

		c.Redirect(http.StatusFound, adminPath+"/users")
	})

	admin.POST("/user/delete/:uid", writeProtectMiddleware, func(c *gin.Context) {
		uid := c.Param("uid")

		// Prevent deleting 'admin' or current user
		var name string
		db.QueryRow("SELECT name FROM typecho_users WHERE uid=?", uid).Scan(&name)
		if name == "admin" {
			c.String(403, "Cannot delete the default admin account")
			return
		}

		currUser, _ := c.Get("username")
		if name == currUser {
			c.String(403, "You cannot delete your own account")
			return
		}

		db.Exec("DELETE FROM typecho_users WHERE uid=?", uid)
		c.Redirect(http.StatusFound, adminPath+"/users")
	})

	admin.POST("/category/delete/:mid", writeProtectMiddleware, func(c *gin.Context) {
		mid := c.Param("mid")
		// Delete category
		db.Exec("DELETE FROM typecho_metas WHERE mid=? AND type='category'", mid)
		// Delete relationships
		db.Exec("DELETE FROM typecho_relationships WHERE mid=?", mid)
		c.Redirect(http.StatusFound, adminPath+"/categories")
	})

	// Backup Management
	admin.GET("/backups", func(c *gin.Context) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")

		os.MkdirAll("backups", 0755)
		files, _ := os.ReadDir("backups")
		var backups []map[string]interface{}
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".tar.gz") {
				info, _ := f.Info()
				backups = append(backups, map[string]interface{}{
					"Name":    f.Name(),
					"Size":    fmt.Sprintf("%.2f MB", float64(info.Size())/(1024*1024)),
					"Time":    info.ModTime().Format("2006-01-02 15:04:05"),
					"RawTime": info.ModTime(),
				})
			}
		}

		// Sort by time descending
		sort.Slice(backups, func(i, j int) bool {
			return backups[i]["RawTime"].(time.Time).After(backups[j]["RawTime"].(time.Time))
		})

		msg := c.Query("msg")
		var successMsg string
		if msg == "created" {
			backupMutex.Lock()
			running := isBackingUp
			backupMutex.Unlock()

			if running {
				successMsg = "备份任务已启动，正在后台处理中..."
			} else {
				successMsg = "备份任务已完成"
			}
		} else if msg == "deleted" {
			successMsg = "备份已删除"
		} else if msg == "vacuumed" {
			successMsg = "数据库压缩完成，无用空间已释放"
		}

		c.HTML(http.StatusOK, "admin_backups.html", gin.H{
			"Username":       username,
			"Backups":        backups,
			"Tab":            "backups",
			"AdminPath":      adminPath,
			"SuccessMessage": successMsg,
			"IsBackingUp":    isBackingUp,
		})
	})

	admin.POST("/backups/create", writeProtectMiddleware, func(c *gin.Context) {
		backupMutex.Lock()
		if isBackingUp {
			backupMutex.Unlock()
			c.HTML(http.StatusOK, "admin_backups.html", gin.H{
				"Username":     c.MustGet("username"),
				"Tab":          "backups",
				"AdminPath":    adminPath,
				"ErrorMessage": "备份任务正在进行中，请在结束后再试。",
			})
			return
		}
		isBackingUp = true
		backupMutex.Unlock()

		go func() {
			defer func() {
				backupMutex.Lock()
				isBackingUp = false
				backupMutex.Unlock()
			}()

			os.MkdirAll("backups", 0755)
			filename := fmt.Sprintf("backup_%s.tar.gz", time.Now().Format("20060102_150405"))
			targetPath := filepath.Join("backups", filename)

			// 确保 WAL 日志中的数据全部合并到主数据库文件，保证备份完整性
			db.Exec("PRAGMA wal_checkpoint(FULL)")

			// Create backup using tar command
			// 使用 sh -c 来让 tar 支持通配符，或者明确列出文件
			cmd := exec.Command("tar", "-czf", targetPath, "blog.sqlite", "usr")
			// 如果你想把 wal/shm 也带上也可以，但 checkpoint 后 blog.sqlite 已经是完整的了
			err := cmd.Run()
			if err != nil {
				log.Printf("Background backup failed: %v", err)
			} else {
				log.Printf("Background backup created: %s", targetPath)
			}
		}()

		c.Redirect(http.StatusFound, adminPath+"/backups?msg=created")
	})

	admin.POST("/backups/delete/:filename", writeProtectMiddleware, func(c *gin.Context) {
		filename := c.Param("filename")
		// 1. 严格检查后缀
		// 2. 强制使用 filepath.Base 获取纯文件名，杜绝任何路径偏移
		// 3. 同时禁止文件名中包含任何路径分隔符
		safeFilename := filepath.Base(filename)
		if !strings.HasSuffix(safeFilename, ".tar.gz") || safeFilename != filename || strings.ContainsAny(filename, `/\`) {
			c.String(400, "非法操作：文件名包含非法路径字符")
			return
		}

		path := filepath.Join("backups", safeFilename)
		os.Remove(path)
		c.Redirect(http.StatusFound, adminPath+"/backups?msg=deleted")
	})

	admin.POST("/backups/vacuum", writeProtectMiddleware, func(c *gin.Context) {
		adminPath, _ := c.Get("adminPath")
		// 之前讨论过：VACUUM 会重新整理数据库文件，回收被删除数据占据的空间
		_, err := db.Exec("VACUUM")
		if err != nil {
			log.Printf("Database vacuum failed: %v", err)
			c.Redirect(http.StatusFound, adminPath.(string)+"/backups?msg=error")
			return
		}
		c.Redirect(http.StatusFound, adminPath.(string)+"/backups?msg=vacuumed")
	})

	admin.POST("/system/restart", writeProtectMiddleware, func(c *gin.Context) {
		// 先重启前台 blog 服务
		go func() {
			// 稍微延迟一下，确保响应能发出
			time.Sleep(1 * time.Second)
			log.Println("收到重启请求，准备重启服务...")

			// 重启 blog 服务 (前台)
			cmdBlog := exec.Command("systemctl", "restart", "blog")
			if err := cmdBlog.Run(); err != nil {
				log.Printf("重启 blog 服务失败: %v", err)
			} else {
				log.Println("blog 服务重启成功")
			}

			// 重启 blogadmin 服务 (后台自己)
			// 注意：这会导致当前进程退出，systemctl 会自动重启它
			cmdAdmin := exec.Command("systemctl", "restart", "blogadmin")
			if err := cmdAdmin.Run(); err != nil {
				log.Printf("重启 blogadmin 服务失败: %v", err)
			}
		}()

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "服务重启指令已发送，请稍等片刻后刷新页面。",
		})
	})

	admin.GET("/edit/:cid", func(c *gin.Context) {
		cid := c.Param("cid")
		var post struct {
			Cid   int
			Title string
			Text  string
			Slug  string
		}

		// Fetch Attachments
		var attachments []map[string]interface{}
		if cid != "new" {
			rows, _ := db.Query("SELECT cid, title, text FROM typecho_contents WHERE type='attachment' AND parent=?", cid)
			if rows != nil {
				defer rows.Close()
				for rows.Next() {
					var attCid int
					var attTitle, attText string
					rows.Scan(&attCid, &attTitle, &attText)
					// attTitle contains the relative path like "/blog/usr/uploads/..."
					displayName := filepath.Base(attTitle)
					attachments = append(attachments, map[string]interface{}{
						"Cid":   attCid,
						"Title": displayName,
						"Path":  attTitle,
					})
				}
			}

			var status string
			err := db.QueryRow("SELECT cid, title, text, slug, status FROM typecho_contents WHERE cid=?", cid).Scan(&post.Cid, &post.Title, &post.Text, &post.Slug, &status)
			if err != nil {
				c.String(404, "未找到文章")
				return
			}
			group, _ := c.Get("userGroup")

			post.Text = strings.TrimPrefix(post.Text, "<!--markdown-->")

			// Fetch post's categories
			postCats := make(map[int]bool)
			rowsP, _ := db.Query("SELECT mid FROM typecho_relationships WHERE cid=?", cid)
			if rowsP != nil {
				defer rowsP.Close()
				for rowsP.Next() {
					var mid int
					rowsP.Scan(&mid)
					postCats[mid] = true
				}
			}

			// Fetch all categories
			var categories []map[string]interface{}
			rowsC, _ := db.Query("SELECT mid, name FROM typecho_metas WHERE type='category' ORDER BY \"order\" ASC, mid ASC")
			if rowsC != nil {
				defer rowsC.Close()
				for rowsC.Next() {
					var mid int
					var name string
					rowsC.Scan(&mid, &name)
					categories = append(categories, map[string]interface{}{
						"Mid":      mid,
						"Name":     name,
						"Selected": postCats[mid],
					})
				}
			}

			username, _ := c.Get("username")
			c.HTML(http.StatusOK, "admin_edit.html", gin.H{
				"Username":    username,
				"UserGroup":   group,
				"Post":        post,
				"IsNew":       false,
				"Attachments": attachments,
				"Tab":         "posts",
				"Categories":  categories,
			})
		} else {
			// Fetch all categories for new post
			defCat := getOption(db, "defaultCategory", "1")
			var categories []map[string]interface{}
			rowsC, _ := db.Query("SELECT mid, name FROM typecho_metas WHERE type='category' ORDER BY \"order\" ASC, mid ASC")
			if rowsC != nil {
				defer rowsC.Close()
				for rowsC.Next() {
					var mid int
					var name string
					rowsC.Scan(&mid, &name)
					selected := fmt.Sprintf("%d", mid) == defCat
					categories = append(categories, map[string]interface{}{
						"Mid":      mid,
						"Name":     name,
						"Selected": selected,
					})
				}
			}
			username, _ := c.Get("username")
			group, _ := c.Get("userGroup")
			if group == "visitor" {
				c.HTML(http.StatusForbidden, "admin_error.html", gin.H{
					"AdminPath":    adminPath,
					"ErrorTitle":   "功能受限",
					"ErrorMessage": "访客模式下无法创建新文章。",
				})
				return
			}
			c.HTML(http.StatusOK, "admin_edit.html", gin.H{
				"Username":    username,
				"UserGroup":   group,
				"Post":        post,
				"IsNew":       true,
				"Attachments": nil,
				"Tab":         "posts",
				"Categories":  categories,
			})
		}
	})

	admin.POST("/attachment/delete/:cid", writeProtectMiddleware, func(c *gin.Context) {
		attCid := c.Param("cid")
		parentCid := c.Query("parent")

		// 1. Get file path from DB
		var relPath string
		err := db.QueryRow("SELECT title FROM typecho_contents WHERE cid=?", attCid).Scan(&relPath)
		if err == nil && relPath != "" {
			// 2. Physical delete
			// Local path is relative to the current directory
			localSubPath := strings.TrimPrefix(relPath, "/blog/")
			absPath := filepath.Join(".", localSubPath)
			os.Remove(absPath)
		}

		// 3. Delete from DB
		db.Exec("DELETE FROM typecho_contents WHERE cid=?", attCid)
		c.Redirect(http.StatusFound, ""+adminPath+"/edit/"+parentCid)
	})

	admin.POST("/post/toggle/:cid", writeProtectMiddleware, func(c *gin.Context) {
		cid := c.Param("cid")
		var currentStatus string
		err := db.QueryRow("SELECT status FROM typecho_contents WHERE cid=?", cid).Scan(&currentStatus)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "文章不存在"})
			return
		}

		newStatus := "publish"
		if currentStatus == "publish" {
			newStatus = "waiting"
		}

		_, err = db.Exec("UPDATE typecho_contents SET status=? WHERE cid=?", newStatus, cid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "newStatus": newStatus})
	})

	admin.POST("/post/toggle-top/:cid", writeProtectMiddleware, func(c *gin.Context) {
		cid := c.Param("cid")
		stickyCidsStr := getOption(db, "sticky_cids", "")
		cids := strings.Split(stickyCidsStr, ",")
		var newCids []string
		found := false
		for _, id := range cids {
			if id == "" {
				continue
			}
			if id == cid {
				found = true
				continue
			}
			newCids = append(newCids, id)
		}
		if !found {
			newCids = append(newCids, cid)
		}
		setOption(db, "sticky_cids", strings.Join(newCids, ","))
		c.JSON(http.StatusOK, gin.H{"success": true, "isTop": !found})
	})

	admin.POST("/save", writeProtectMiddleware, func(c *gin.Context) {
		cid := c.PostForm("cid")
		title := c.PostForm("title")
		text := c.PostForm("text")
		slug := strings.TrimSpace(c.PostForm("slug"))
		if slug == "" {
			// 如果 slug 为空，生成一个临时的（后续可能被 CID 替换或保持）
			slug = fmt.Sprintf("post-%d", time.Now().Unix())
		}

		// 确保 slug 唯一性
		checkUnique := func(s string, currentCid string) string {
			var count int
			finalSlug := s
			for i := 0; i < 10; i++ { // 最多尝试10次重命名
				if currentCid == "0" || currentCid == "" {
					db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE slug=?", finalSlug).Scan(&count)
				} else {
					db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE slug=? AND cid!=?", finalSlug, currentCid).Scan(&count)
				}
				if count == 0 {
					return finalSlug
				}
				// 如果冲突，追加随机后缀
				finalSlug = fmt.Sprintf("%s-%d", s, time.Now().UnixNano()%1000)
			}
			return finalSlug
		}

		slug = checkUnique(slug, cid)

		if !strings.HasPrefix(text, "<!--markdown-->") {
			text = "<!--markdown-->" + text
		}

		var finalCid string
		if cid == "0" || cid == "" {
			// New post
			now := time.Now().Unix()
			res, err := db.Exec("INSERT INTO typecho_contents (title, slug, created, modified, text, authorId, type, status) VALUES (?, ?, ?, ?, ?, 1, 'post', 'publish')", title, slug, now, now, text)
			if err != nil {
				c.String(500, err.Error())
				return
			}
			newId, _ := res.LastInsertId()
			finalCid = fmt.Sprintf("%d", newId)
			// Claim orphan attachments (legacy)
			db.Exec("UPDATE typecho_contents SET parent=? WHERE parent=0 AND type='attachment' AND authorId=1", newId)
		} else {
			// Update
			now := time.Now().Unix()
			_, err := db.Exec("UPDATE typecho_contents SET title=?, slug=?, text=?, modified=? WHERE cid=?", title, slug, text, now, cid)
			if err != nil {
				c.String(500, err.Error())
				return
			}
			finalCid = cid
		}

		// Auto-associate attachments found in text
		re := regexp.MustCompile(`!\[.*?\]\((/blog/usr/uploads/.*?)\)`)
		matches := re.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				imgPath := match[1]
				var existingCid int
				err := db.QueryRow("SELECT cid FROM typecho_contents WHERE title=? AND type='attachment'", imgPath).Scan(&existingCid)

				if err == nil {
					// Update existing
					db.Exec("UPDATE typecho_contents SET parent=? WHERE cid=?", finalCid, existingCid)
				} else {
					// Create missing record for file that exists on disk
					fileName := filepath.Base(imgPath)
					now := time.Now().Unix()
					db.Exec("INSERT INTO typecho_contents (title, slug, created, modified, text, authorId, type, status, parent) VALUES (?, ?, ?, ?, ?, 1, 'attachment', 'publish', ?)",
						imgPath, fileName, now, now, "", finalCid)
				}
			}
		}

		c.Redirect(http.StatusFound, ""+adminPath+"/edit/"+finalCid+"?msg=saved")

		// Update categories
		categories := c.PostFormArray("categories")
		db.Exec("DELETE FROM typecho_relationships WHERE cid=?", finalCid)
		if len(categories) == 0 {
			defCat := getOption(db, "defaultCategory", "1")
			db.Exec("INSERT INTO typecho_relationships (cid, mid) VALUES (?, ?)", finalCid, defCat)
		} else {
			for _, mid := range categories {
				db.Exec("INSERT INTO typecho_relationships (cid, mid) VALUES (?, ?)", finalCid, mid)
			}
		}
	})

	// Attachment Upload (Relative Path Fix)
	admin.POST("/upload", writeProtectMiddleware, func(c *gin.Context) {
		parentCid := c.PostForm("cid")
		file, err := c.FormFile("editormd-image-file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": 0, "message": "上传失败"})
			return
		}

		now := time.Now()
		relDir := fmt.Sprintf("usr/uploads/%d/%02d", now.Year(), now.Month())
		absDir := filepath.Join(".", relDir)
		os.MkdirAll(absDir, 0755)

		fileName := fmt.Sprintf("%d_%s", now.UnixNano(), file.Filename)
		absPath := filepath.Join(absDir, fileName)
		relPath := "/" + filepath.Join("blog", relDir, fileName)

		if err := c.SaveUploadedFile(file, absPath); err != nil {
			c.JSON(500, gin.H{"success": 0, "message": err.Error()})
			return
		}

		// Register in database as attachment
		if parentCid != "" {
			db.Exec("INSERT INTO typecho_contents (title, slug, created, modified, text, authorId, type, status, parent) VALUES (?, ?, ?, ?, ?, 1, 'attachment', 'publish', ?)",
				relPath, fileName, now.Unix(), now.Unix(), "", parentCid)
		}

		c.JSON(http.StatusOK, gin.H{
			"success": 1,
			"message": "上传成功",
			"url":     relPath,
		})
	})

	log.Println("Admin Server starting on 127.0.0.1:8191")
	r.Run("127.0.0.1:8191")
}

func checkTypechoHash(password, hash string) bool {
	return cryptPrivate(password, hash) == hash
}

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func encode64(input []byte, count int) string {
	res := ""
	i := 0
	for {
		value := int(input[i])
		i++
		res += string(itoa64[value&0x3f])
		if i < count {
			value |= int(input[i]) << 8
		}
		res += string(itoa64[(value>>6)&0x3f])
		if i >= count {
			break
		}
		i++
		if i < count {
			value |= int(input[i]) << 16
		}
		res += string(itoa64[(value>>12)&0x3f])
		if i >= count {
			break
		}
		i++
		res += string(itoa64[(value>>18)&0x3f])
		if i >= count {
			break
		}
	}
	return res
}

func hashTypecho(password string) string {
	salt := uuid.New().String()[:8]
	setting := "$P$" + string(itoa64[8]) + salt
	return cryptPrivate(password, setting)
}

func getOption(db *sql.DB, name string, defaultValue string) string {
	var val string
	err := db.QueryRow("SELECT value FROM go_options WHERE name=?", name).Scan(&val)
	if err == nil {
		return val
	}
	// Fallback to typecho_options
	err = db.QueryRow("SELECT value FROM typecho_options WHERE name=? AND user=0", name).Scan(&val)
	if err == nil {
		return val
	}
	return defaultValue
}

func getOptionInt(db *sql.DB, name string, defaultValue int) int {
	val := getOption(db, name, "")
	if val == "" {
		return defaultValue
	}
	var i int
	fmt.Sscanf(val, "%d", &i)
	if i == 0 {
		return defaultValue
	}
	return i
}

func setOption(db *sql.DB, name string, value string) {
	_, err := db.Exec("INSERT INTO go_options (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", name, value)
	if err != nil {
		log.Printf("Error setting option %s: %v", name, err)
	}
}

func cryptPrivate(password string, setting string) string {
	if !strings.HasPrefix(setting, "$P$") && !strings.HasPrefix(setting, "$H$") {
		return "*"
	}
	countLog2 := strings.Index(itoa64, string(setting[3]))
	if countLog2 < 7 || countLog2 > 30 {
		return "*"
	}
	count := 1 << uint(countLog2)
	salt := setting[4:12]
	hash := md5.Sum([]byte(salt + password))
	h := hash[:]
	for i := 0; i < count; i++ {
		newHash := md5.Sum(append(h, []byte(password)...))
		h = newHash[:]
	}
	return setting[:12] + encode64(h, 16)
}
