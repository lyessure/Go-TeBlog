package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
	_ "modernc.org/sqlite"
)

type statsLog struct {
	IP    string
	UA    string
	Path  string
	IsBot int
}

var statsChan chan statsLog
var statsWG sync.WaitGroup

func startStatsWorker(db *sql.DB) {
	statsWG.Add(1)
	defer statsWG.Done()
	for logEntry := range statsChan {
		_, err := db.Exec("INSERT INTO go_stats_logs (ip, ua, path, is_bot, created) VALUES (?, ?, ?, ?, ?)",
			logEntry.IP, logEntry.UA, logEntry.Path, logEntry.IsBot, time.Now().Unix())
		if err != nil {
			log.Printf("Error writing stats log: %v", err)
		}
	}
	log.Println("Statistics worker: all queued logs written to database.")
}

func startJanitor(db *sql.DB) {
	for {
		retentionDays := getOptionInt(db, "logRetentionDays", 30)
		if retentionDays > 0 {
			cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
			res, err := db.Exec("DELETE FROM go_stats_logs WHERE created < ?", cutoff)
			if err != nil {
				log.Printf("Janitor error: %v", err)
			} else {
				rows, _ := res.RowsAffected()
				if rows > 0 {
					log.Printf("Janitor: cleaned up %d old log records.", rows)
				}
			}
		}
		// 每小时检查一次
		time.Sleep(1 * time.Hour)
	}
}

type Post struct {
	Cid         int
	Title       string
	Slug        string
	Created     int64
	Text        string
	CommentsNum int
	AuthorId    int
	Author      string
	Categories  []Category
}

type Category struct {
	Mid  int
	Name string
	Slug string
}

type Comment struct {
	Coid    int
	Cid     int
	Author  string
	Text    string
	Created int64
}

type Tag struct {
	Name string
	Slug string
}

type PostDetailData struct {
	Site            SiteInfo
	Post            Post
	Tags            []Tag
	Comments        []Comment
	PrevPost        *Post
	NextPost        *Post
	RecentPosts     []Post
	RecentComments  []Comment
	Categories      []Category
	CurrentSlug     string
	CommentsEnabled bool
}
type SiteInfo struct {
	Title       string
	Description string
	Keywords    string
	Theme       string
	SiteUrl     string
	FooterCode  template.HTML
}

type PageData struct {
	Site           SiteInfo
	Posts          []Post
	RecentPosts    []Post
	Categories     []Category
	RecentComments []Comment
	SearchQuery    string
	ArchiveTitle   string
	PaginationBase string
	CurrentSlug    string
	CurrentPage    int
	TotalPages     int
	HasPrev        bool
	HasNext        bool
	PrevPage       int
	NextPage       int
}

func statsMiddleware(db *sql.DB, adminPath string) gin.HandlerFunc {
	// 定义需要排除的静态资源扩展名
	assetExts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"}

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		pathLower := strings.ToLower(path)

		// 基础排除逻辑
		isAsset := false
		for _, ext := range assetExts {
			if strings.HasSuffix(pathLower, ext) {
				isAsset = true
				break
			}
		}

		// 检查路径前缀排除
		if c.Request.Method == "GET" &&
			!isAsset &&
			!strings.HasPrefix(path, adminPath) &&
			!strings.HasPrefix(path, "/usr") &&
			!strings.HasPrefix(path, "/blog/usr") &&
			!strings.HasPrefix(path, "/static") &&
			!strings.Contains(pathLower, "favicon") {

			ua := c.Request.UserAgent()
			uaLower := strings.ToLower(ua)

			// 机器人/扫描器检测
			isBot := 0
			// 增加更广泛的自动化工具和搜索引擎特征
			if strings.Contains(uaLower, "bot") ||
				strings.Contains(uaLower, "spider") ||
				strings.Contains(uaLower, "crawler") ||
				strings.Contains(uaLower, "google") ||
				strings.Contains(uaLower, "bing") ||
				strings.Contains(uaLower, "baidu") ||
				strings.Contains(uaLower, "sogou") ||
				strings.Contains(uaLower, "360spider") ||
				strings.Contains(uaLower, "haosouspider") ||
				strings.Contains(uaLower, "yisouspider") ||
				strings.Contains(uaLower, "yahoo") ||
				strings.Contains(uaLower, "duckduckgo") ||
				strings.Contains(uaLower, "yandex") ||
				strings.Contains(uaLower, "applebot") ||
				strings.Contains(uaLower, "curl") ||
				strings.Contains(uaLower, "wget") ||
				strings.Contains(uaLower, "scan") ||
				strings.Contains(uaLower, "reader") ||
				strings.Contains(uaLower, "rss") ||
				strings.Contains(uaLower, "paloalto") ||
				strings.Contains(uaLower, "headless") ||
				strings.Contains(uaLower, "python") ||
				strings.Contains(uaLower, "go-http-client") {
				isBot = 1
			}

			// 优先从 Cloudflare 变量获取 IP
			ip := c.GetHeader("CF-Connecting-IP")
			if ip == "" {
				ip = c.ClientIP()
			}

			// 排除内网 IP 的统计（可选，如果你希望排除自己或内网网关的访问）
			if strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.0.0.") {
				isBot = 1
			}

			// 算法变更：在中间件中，只记录确定是机器人的流量
			// 真人流量由页面底部的 beacon 触发异步接口记录
			if isBot == 1 {
				select {
				case statsChan <- statsLog{
					IP:    ip,
					UA:    ua,
					Path:  path,
					IsBot: 1,
				}:
				default:
				}
			}
		}
		c.Next()
	}
}

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseBodyWriter) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func beaconMiddleware(adminPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		// 只拦截 GET 请求，且排除后台路径和静态资源路径
		if c.Request.Method != "GET" ||
			strings.HasPrefix(path, adminPath) ||
			strings.HasPrefix(path, "/usr") ||
			strings.HasPrefix(path, "/static") {
			c.Next()
			return
		}

		w := &responseBodyWriter{body: &bytes.Buffer{}, ResponseWriter: c.Writer}
		c.Writer = w
		c.Next()

		contentType := w.Header().Get("Content-Type")
		if strings.Contains(contentType, "text/html") && w.Status() == http.StatusOK {
			script := `<script>(function(){var _0x=['/a','pi','/sta','ts/b','eaco','n'];var _0y=_0x.join('');var b=new Image();b.src=_0y+'?path='+encodeURIComponent(window.location.pathname)+'&t='+(new Date()).getTime();})();</script>`
			content := w.body.String()
			lowerContent := strings.ToLower(content)
			// 优先在 <head> 内注入；没有 <head> 就紧接 <html> 之后；两者都没有则插入 </body> 前
			if idx := strings.Index(lowerContent, "<head"); idx != -1 {
				if endIdx := strings.Index(content[idx:], ">"); endIdx != -1 {
					insertPos := idx + endIdx + 1
					content = content[:insertPos] + script + content[insertPos:]
				} else {
					content += script
				}
			} else if idx := strings.Index(lowerContent, "<html"); idx != -1 {
				if endIdx := strings.Index(content[idx:], ">"); endIdx != -1 {
					insertPos := idx + endIdx + 1
					content = content[:insertPos] + script + content[insertPos:]
				} else {
					content += script
				}
			} else if idx := strings.LastIndex(lowerContent, "</body>"); idx != -1 {
				content = content[:idx] + script + content[idx:]
			} else {
				content += script
			}
			// 必须设置新的 Content-Length，否则浏览器可能会截断
			w.Header().Set("Content-Length", fmt.Sprint(len(content)))
			w.ResponseWriter.Write([]byte(content))
		} else {
			w.ResponseWriter.Write(w.body.Bytes())
		}
	}
}

func handleBeacon(c *gin.Context) {
	ua := c.Request.UserAgent()
	uaLower := strings.ToLower(ua)

	// 排除主流搜索引擎和机器人，因为它们也可能访问 beacon
	if strings.Contains(uaLower, "bot") ||
		strings.Contains(uaLower, "spider") ||
		strings.Contains(uaLower, "crawler") ||
		strings.Contains(uaLower, "google") ||
		strings.Contains(uaLower, "bing") ||
		strings.Contains(uaLower, "baidu") ||
		strings.Contains(uaLower, "sogou") ||
		strings.Contains(uaLower, "360spider") ||
		strings.Contains(uaLower, "haosouspider") ||
		strings.Contains(uaLower, "yisouspider") ||
		strings.Contains(uaLower, "yahoo") ||
		strings.Contains(uaLower, "duckduckgo") ||
		strings.Contains(uaLower, "yandex") ||
		strings.Contains(uaLower, "applebot") {
		c.Status(http.StatusNoContent)
		return
	}

	ip := c.GetHeader("CF-Connecting-IP")
	if ip == "" {
		ip = c.ClientIP()
	}

	isBot := 0
	if strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.0.0.") {
		isBot = 1
	}

	path := c.Query("path")
	if path == "" {
		path = "/"
	}

	select {
	case statsChan <- statsLog{
		IP:    ip,
		UA:    ua,
		Path:  path,
		IsBot: isBot,
	}:
	default:
	}

	c.Status(http.StatusNoContent)
}

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

	// Initialize database schema
	initDB(db)

	// 配置统计缓存队列大小
	bufferSize := getOptionInt(db, "statsBufferSize", 100)
	statsChan = make(chan statsLog, bufferSize)

	// 启动后台统计处理协程
	go startStatsWorker(db)
	// 启动后台清理协程
	go startJanitor(db)

	// 优化 SQLite 性能
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA synchronous=NORMAL")

	r := gin.Default()
	r.SetTrustedProxies(nil)

	adminPath := getOption(db, "adminPath", "admin")
	if !strings.HasPrefix(adminPath, "/") {
		adminPath = "/" + adminPath
	}
	adminPath = strings.TrimSuffix(adminPath, "/")

	// 应用访问统计中间件
	r.Use(statsMiddleware(db, adminPath))
	// 应用 Beacon 动态注入中间件 (排除后台)
	r.Use(beaconMiddleware(adminPath))

	// 核心逻辑：动态后台路径的反向代理
	// 前台服务 (8190) 监听所有流量，发现匹配 adminPath 时中转给后台 (8191)
	handleProxy := func(c *gin.Context) {
		target, _ := url.Parse("http://127.0.0.1:8191")
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(c.Writer, c.Request)
	}
	r.Any(adminPath, handleProxy)
	r.Any(adminPath+"/*any", handleProxy)

	// Configure Markdown renderer
	mdRenderer := goldmark.New(
		goldmark.WithExtensions(extension.Linkify),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithUnsafe(),
		),
	)

	// Serve static files from usr folder
	r.Static("/usr", "./usr")
	r.Static("/blog/usr", "./usr")

	// Fallback to static folder for root-level files
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		fullPath := filepath.Join("./static", path)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			c.File(fullPath)
			return
		}
		c.String(http.StatusNotFound, "404 page not found")
	})

	r.SetFuncMap(template.FuncMap{
		"formatDate": func(t int64) string {
			return time.Unix(t, 0).Format("2006-01-02")
		},
		"formatDateTime": func(t int64) string {
			return time.Unix(t, 0).Format("2006-01-02T15:04:05Z07:00")
		},
		"now": func() time.Time {
			return time.Now()
		},
		"substring": func(text string, maxLen int) string {
			runes := []rune(text)
			if len(runes) <= maxLen {
				return text
			}
			return string(runes[:maxLen]) + "..."
		},
		"targetPage": func(base string, p int, search string) string {
			if search != "" {
				// Typecho search pagination: /blog/index.php/search/{keyword}/{page}/
				if p == 1 {
					return fmt.Sprintf("/blog/index.php/search/%s/", search)
				}
				return fmt.Sprintf("/blog/index.php/search/%s/%d/", search, p)
			}

			suffix := ""
			if !strings.HasSuffix(base, "/") {
				suffix = "/"
			}

			url := base
			if p > 1 {
				url = fmt.Sprintf("%s%spage/%d/", base, suffix, p)
			}
			return url
		},
		"paginationRange": func(current, total int) []interface{} {
			var res []interface{}
			if total <= 1 {
				return res
			}

			delta := 2
			res = append(res, 1)

			start := current - delta
			if start < 2 {
				start = 2
			}
			end := current + delta
			if end >= total {
				end = total - 1
			}

			if start > 2 {
				res = append(res, "...")
			}

			for i := start; i <= end; i++ {
				res = append(res, i)
			}

			if end < total-1 {
				res = append(res, "...")
			}

			res = append(res, total)

			return res
		},
		"isStr": func(val interface{}) bool {
			_, ok := val.(string)
			return ok
		},
		"fullContent": func(p Post) template.HTML {
			content := strings.TrimPrefix(p.Text, "<!--markdown-->")
			parts := strings.Split(content, "<!--more-->")
			excerpt := parts[0]

			var buf bytes.Buffer
			if err := mdRenderer.Convert([]byte(excerpt), &buf); err != nil {
				return template.HTML(excerpt)
			}

			htmlContent := buf.String()

			// If <!--more--> was found, append the "Read more" link
			if len(parts) > 1 {
				moreLink := fmt.Sprintf("<p class=\"more\"><a href=\"/blog/index.php/archives/%d/\" title=\"%s\">- 阅读剩余部分 -</a></p>", p.Cid, p.Title)
				htmlContent += moreLink
			}

			return template.HTML(htmlContent)
		},
		"renderMarkdown": func(text string) template.HTML {
			content := strings.TrimPrefix(text, "<!--markdown-->")
			var buf bytes.Buffer
			if err := mdRenderer.Convert([]byte(content), &buf); err != nil {
				return template.HTML(content)
			}
			return template.HTML(buf.String())
		},
		"permalink": func(p Post) string {
			// Typecho default permalink: index.php/archives/{cid}/
			return fmt.Sprintf("/blog/index.php/archives/%d/", p.Cid)
		},
		"catPermalink": func(c Category) string {
			return fmt.Sprintf("/blog/index.php/category/%s/", c.Slug)
		},
		"commPermalink": func(c Comment) string {
			return fmt.Sprintf("/blog/index.php/archives/%d/#comment-%d", c.Cid, c.Coid)
		},
		"contains":  strings.Contains,
		"adminPath": func() string { return adminPath },
	})

	r.LoadHTMLGlob("templates/frontend/*")

	handleIndex := func(c *gin.Context) {
		s := c.Query("s")
		if s == "" {
			s = c.PostForm("s")
		}

		pageStr := c.Param("page")
		if pageStr == "" {
			pageStr = c.DefaultQuery("page", "1")
		}
		var page int
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := getOptionInt(db, "pageSize", 10)

		site := getSiteInfo(db)
		posts, total := getPosts(db, page, pageSize, s)
		recentPosts := getRecentPostsSidebar(db, "")
		categories := getCategories(db)
		recentComments := getRecentComments(db, "")

		totalPages := (total + pageSize - 1) / pageSize

		c.HTML(http.StatusOK, "index.html", PageData{
			Site:           site,
			Posts:          posts,
			RecentPosts:    recentPosts,
			Categories:     categories,
			RecentComments: recentComments,
			SearchQuery:    s,
			PaginationBase: "/blog/index.php/",
			CurrentSlug:    "",
			CurrentPage:    page,
			TotalPages:     totalPages,
			HasPrev:        page > 1,
			HasNext:        page < totalPages,
			PrevPage:       page - 1,
			NextPage:       page + 1,
		})
	}

	handleSearchRedirect := func(c *gin.Context) {
		s := c.PostForm("s")
		if s == "" {
			s = c.Query("s")
		}
		if s != "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("/blog/index.php/search/%s/", s))
			return
		}
		c.Redirect(http.StatusFound, "/blog/")
	}

	handleSearch := func(c *gin.Context) {
		s := c.Param("keyword")
		pageStr := c.Param("page")
		if pageStr == "" {
			pageStr = "1"
		}
		var page int
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := getOptionInt(db, "pageSize", 10)

		site := getSiteInfo(db)
		posts, total := getPosts(db, page, pageSize, s)
		recentPosts := getRecentPostsSidebar(db, "")
		categories := getCategories(db)
		recentComments := getRecentComments(db, "")

		totalPages := (total + pageSize - 1) / pageSize

		c.HTML(http.StatusOK, "index.html", PageData{
			Site:           site,
			Posts:          posts,
			RecentPosts:    recentPosts,
			Categories:     categories,
			RecentComments: recentComments,
			SearchQuery:    s,
			PaginationBase: fmt.Sprintf("/blog/index.php/search/%s/", s),
			CurrentPage:    page,
			TotalPages:     totalPages,
			HasPrev:        page > 1,
			HasNext:        page < totalPages,
			PrevPage:       page - 1,
			NextPage:       page + 1,
		})
	}

	handlePost := func(c *gin.Context) {
		cidStr := c.Param("cid")
		var cid int
		fmt.Sscanf(cidStr, "%d", &cid)

		site := getSiteInfo(db)
		post, ok := getPost(db, cid)
		if !ok {
			c.String(http.StatusNotFound, "Post not found")
			return
		}

		// Check if any category of this post is offline
		for _, cat := range post.Categories {
			var isOffline int
			db.QueryRow("SELECT is_offline FROM go_category_settings WHERE mid=?", cat.Mid).Scan(&isOffline)
			if isOffline == 1 {
				c.HTML(http.StatusNotFound, "error.html", gin.H{
					"Site":         site,
					"ErrorTitle":   "文章不可用",
					"ErrorMessage": "抱歉，该文章所属分类已下线，暂时无法访问。",
				})
				return
			}
		}

		tags := getPostTags(db, cid)
		comments := getPostComments(db, cid)
		prev, next := getPrevNextPosts(db, post.Created)
		// Determine current category slug for navigation highlighting and sidebar context
		currentSlug := ""
		if len(post.Categories) > 0 {
			currentSlug = post.Categories[0].Slug
		}

		recentPosts := getRecentPostsSidebar(db, currentSlug)
		categories := getCategories(db)
		recentComments := getRecentComments(db, currentSlug)

		c.HTML(http.StatusOK, "post.html", PostDetailData{
			Site:            site,
			Post:            post,
			Tags:            tags,
			Comments:        comments,
			PrevPost:        prev,
			NextPost:        next,
			RecentPosts:     recentPosts,
			Categories:      categories,
			RecentComments:  recentComments,
			CurrentSlug:     currentSlug,
			CommentsEnabled: getOption(db, "commentsEnabled", "1") == "1",
		})
	}

	handleComment := func(c *gin.Context) {
		cidStr := c.Param("cid")
		var cid int
		fmt.Sscanf(cidStr, "%d", &cid)

		// 0. Global Comments Enabled Check
		if getOption(db, "commentsEnabled", "1") != "1" {
			site := getSiteInfo(db)
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "评论已关闭",
				"ErrorMessage": "抱歉，本站已暂时关闭评论功能。您可以继续阅读文章。",
			})
			return
		}

		ip := c.ClientIP()
		now := time.Now().Unix()
		oneMinuteAgo := now - 60

		// 1. IP Rate Limit Check
		limitIP := getOptionInt(db, "commentLimitIP", 1)
		var countIP int
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments WHERE ip=? AND created > ?", ip, oneMinuteAgo).Scan(&countIP)
		if countIP >= limitIP {
			site := getSiteInfo(db)
			c.HTML(http.StatusTooManyRequests, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "提交过于频繁",
				"ErrorMessage": "抱歉，您提交评论的速度过快。请稍后再试。",
			})
			return
		}

		// 2. Global Rate Limit Check
		limitGlobal := getOptionInt(db, "commentLimitGlobal", 2)
		var countGlobal int
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments WHERE created > ?", oneMinuteAgo).Scan(&countGlobal)
		if countGlobal >= limitGlobal {
			site := getSiteInfo(db)
			c.HTML(http.StatusTooManyRequests, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "系统繁忙",
				"ErrorMessage": "目前全站评论提交过于密集，请稍候片刻再试。",
			})
			return
		}

		author := c.PostForm("author")
		words := c.PostForm("words")
		if author == "" || words == "" {
			site := getSiteInfo(db)
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "表单验证失败",
				"ErrorMessage": "称呼和内容不能为空，请填写完整后再提交。",
			})
			return
		}

		// AI Spam Check
		apiKey := getOption(db, "grokApiKey", "")
		if apiKey != "" {
			apiUrl := getOption(db, "aiApiUrl", "https://api.groq.com/openai/v1/chat/completions")
			model := getOption(db, "aiModel", "llama-3.3-70b-versatile")
			threshold := getOptionInt(db, "aiThreshold", 5)
			score := checkSpamAI(words, apiKey, apiUrl, model)
			if score > threshold {
				site := getSiteInfo(db)
				c.HTML(http.StatusForbidden, "error.html", gin.H{
					"Site":         site,
					"ErrorTitle":   "评论被拒绝",
					"ErrorMessage": "抱歉，系统检测到您的评论可能包含不当内容。如果这是误判，请修改后重新提交。",
				})
				return
			}
		}

		// Get post author for ownerId
		var ownerId int
		err := db.QueryRow("SELECT authorId FROM typecho_contents WHERE cid=?", cid).Scan(&ownerId)
		if err != nil {
			site := getSiteInfo(db)
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "数据库错误",
				"ErrorMessage": "系统无法获取文章信息，请稍后重试。",
			})
			return
		}

		agent := c.Request.UserAgent()

		// Handle comment audit setting
		auditEnabled := getOption(db, "commentAudit", "0") == "1"
		initialStatus := "approved"
		if auditEnabled {
			initialStatus = "waiting"
		}

		_, err = db.Exec(`
			INSERT INTO typecho_comments (cid, created, author, authorId, ownerId, ip, agent, text, type, status, parent)
			VALUES (?, ?, ?, 0, ?, ?, ?, ?, 'comment', ?, 0)`,
			cid, now, author, ownerId, ip, agent, words, initialStatus)

		if err != nil {
			site := getSiteInfo(db)
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "保存失败",
				"ErrorMessage": "评论保存时出现错误，请稍后重试。",
			})
			return
		}

		// Update commentsNum (only if approved)
		if initialStatus == "approved" {
			db.Exec("UPDATE typecho_contents SET commentsNum = commentsNum + 1 WHERE cid = ?", cid)
		}

		// If it needs audit, show a message instead of redirecting
		if initialStatus == "waiting" {
			site := getSiteInfo(db)
			c.HTML(http.StatusOK, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "评论已提交",
				"ErrorMessage": "您的评论已成功提交，正在等待管理员审核。审核通过后将正式显示。",
			})
			return
		}

		c.Redirect(http.StatusFound, fmt.Sprintf("/blog/index.php/archives/%d/", cid))
	}

	handleCategory := func(c *gin.Context) {
		slug := c.Param("slug")
		pageStr := c.Param("page")
		if pageStr == "" {
			pageStr = "1"
		}
		var page int
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := getOptionInt(db, "pageSize", 10)

		site := getSiteInfo(db)

		// Find category name by slug and check offline status
		var catName string
		var isOffline int
		db.QueryRow(`SELECT m.name, COALESCE(s.is_offline, 0) 
                     FROM typecho_metas m 
                     LEFT JOIN go_category_settings s ON m.mid = s.mid 
                     WHERE m.slug=? AND m.type='category'`, slug).Scan(&catName, &isOffline)

		if catName == "" || isOffline == 1 {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"Site":         site,
				"ErrorTitle":   "分类不存在",
				"ErrorMessage": "抱歉，您访问的分类不存在或已被下线。",
			})
			return
		}

		posts, total := getPostsByCategory(db, page, pageSize, slug)
		recentPosts := getRecentPostsSidebar(db, slug)
		categories := getCategories(db)
		recentComments := getRecentComments(db, slug)

		totalPages := (total + pageSize - 1) / pageSize

		c.HTML(http.StatusOK, "index.html", PageData{
			Site:           site,
			Posts:          posts,
			RecentPosts:    recentPosts,
			Categories:     categories,
			RecentComments: recentComments,
			ArchiveTitle:   fmt.Sprintf("分类 %s 下的文章", catName),
			PaginationBase: fmt.Sprintf("/blog/index.php/category/%s/", slug),
			CurrentSlug:    slug,
			CurrentPage:    page,
			TotalPages:     totalPages,
			HasPrev:        page > 1,
			HasNext:        page < totalPages,
			PrevPage:       page - 1,
			NextPage:       page + 1,
		})
	}

	r.GET("/blog", handleIndex)
	r.GET("/blog/", handleIndex)
	r.GET("/blog/index.php", handleIndex)
	r.GET("/blog/index.php/", handleIndex)
	r.POST("/blog", handleSearchRedirect)
	r.POST("/blog/", handleSearchRedirect)
	r.POST("/blog/index.php", handleSearchRedirect)
	r.POST("/blog/index.php/", handleSearchRedirect)
	r.GET("/blog/index.php/page/:page", handleIndex)
	r.GET("/blog/index.php/search/:keyword", handleSearch)
	r.GET("/blog/index.php/search/:keyword/", handleSearch)
	r.GET("/blog/index.php/search/:keyword/:page", handleSearch)
	r.GET("/blog/index.php/search/:keyword/:page/", handleSearch)
	r.GET("/blog/index.php/category/:slug", handleCategory)
	r.GET("/blog/index.php/category/:slug/", handleCategory)
	r.GET("/blog/index.php/category/:slug/page/:page", handleCategory)
	r.GET("/blog/index.php/category/:slug/page/:page/", handleCategory)
	r.GET("/blog/index.php/archives/:cid", handlePost)
	r.GET("/blog/index.php/archives/:cid/", handlePost)
	r.POST("/blog/index.php/archives/:cid/comment", handleComment)
	r.GET("/blog/archives/:cid", handlePost)
	r.GET("/blog/archives/:cid/", handlePost)
	r.GET("/api/stats/beacon", handleBeacon)

	srv := &http.Server{
		Addr:    "127.0.0.1:8190",
		Handler: r,
	}

	// 监听信号的通道
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Println("Server starting on :8190")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// 等待退出信号
	<-quit
	log.Println("Shutting down server...")

	// 1. 先关闭 HTTP 服务，停止接收新请求
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	// 2. 关闭统计通道并等待数据写完
	log.Println("Waiting for statistics worker to finish...")
	close(statsChan)
	statsWG.Wait()

	log.Println("Server exiting")
}

func initDB(db *sql.DB) {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS "typecho_comments" (
			"coid" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"cid" INTEGER DEFAULT 0,
			"created" INTEGER DEFAULT 0,
			"author" VARCHAR(150),
			"authorId" INTEGER DEFAULT 0,
			"ownerId" INTEGER DEFAULT 0,
			"mail" VARCHAR(150),
			"url" VARCHAR(255),
			"ip" VARCHAR(64),
			"agent" VARCHAR(511),
			"text" TEXT,
			"type" VARCHAR(16) DEFAULT 'comment',
			"status" VARCHAR(16) DEFAULT 'approved',
			"parent" INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS "typecho_contents" (
			"cid" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"title" VARCHAR(150),
			"slug" VARCHAR(150) UNIQUE,
			"created" INTEGER DEFAULT 0,
			"modified" INTEGER DEFAULT 0,
			"text" LONGTEXT,
			"order" INTEGER DEFAULT 0,
			"authorId" INTEGER DEFAULT 0,
			"template" VARCHAR(32),
			"type" VARCHAR(16) DEFAULT 'post',
			"status" VARCHAR(16) DEFAULT 'publish',
			"password" VARCHAR(32),
			"commentsNum" INTEGER DEFAULT 0,
			"allowComment" CHAR(1) DEFAULT '0',
			"allowPing" CHAR(1) DEFAULT '0',
			"allowFeed" CHAR(1) DEFAULT '0',
			"parent" INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS "typecho_metas" (
			"mid" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"name" VARCHAR(150),
			"slug" VARCHAR(150),
			"type" VARCHAR(32) NOT NULL,
			"description" VARCHAR(150),
			"count" INTEGER DEFAULT 0,
			"order" INTEGER DEFAULT 0,
			"parent" INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS "typecho_options" (
			"name" VARCHAR(32) NOT NULL,
			"user" INTEGER NOT NULL DEFAULT 0,
			"value" TEXT,
			PRIMARY KEY ("name", "user")
		)`,
		`CREATE TABLE IF NOT EXISTS "typecho_relationships" (
			"cid" INTEGER NOT NULL,
			"mid" INTEGER NOT NULL,
			PRIMARY KEY ("cid", "mid")
		)`,
		`CREATE TABLE IF NOT EXISTS "typecho_users" (
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
		)`,
		`CREATE TABLE IF NOT EXISTS "go_sessions" (
			"session_id" TEXT PRIMARY KEY,
			"username" TEXT,
			"created_at" INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS "go_options" (
			"name" TEXT PRIMARY KEY,
			"value" TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS "go_category_settings" (
			"mid" INTEGER PRIMARY KEY,
			"show_on_home" INTEGER DEFAULT 1,
			"is_offline" INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS "go_stats_logs" (
			"id" INTEGER PRIMARY KEY AUTOINCREMENT,
			"ip" VARCHAR(64),
			"ua" VARCHAR(511),
			"path" VARCHAR(255),
			"is_bot" INTEGER DEFAULT 0,
			"created" INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS "idx_stats_created" ON "go_stats_logs" ("created")`,
		`CREATE INDEX IF NOT EXISTS "idx_stats_bot" ON "go_stats_logs" ("is_bot")`,
	}

	for _, s := range schema {
		_, err := db.Exec(s)
		if err != nil {
			log.Printf("Error creating table: %v", err)
		}
	}

	// Bootstrap a default category if none exists
	var catCount int
	db.QueryRow("SELECT COUNT(*) FROM typecho_metas WHERE type='category'").Scan(&catCount)
	if catCount == 0 {
		res, err := db.Exec("INSERT INTO typecho_metas (name, slug, type, description) VALUES (?, ?, ?, ?)", "默认分类", "default", "category", "由系统自动创建的默认分类")
		if err == nil {
			lastId, _ := res.LastInsertId()
			// Set as default in go_options if not exists
			db.Exec("INSERT INTO go_options (name, value) VALUES ('defaultCategory', ?) ON CONFLICT(name) DO NOTHING", fmt.Sprintf("%d", lastId))
		}
	}

	// Initialize default options if empty
	var count int
	db.QueryRow("SELECT COUNT(*) FROM typecho_options").Scan(&count)
	if count == 0 {
		options := map[string]string{
			"title":       "我的 Go 博客",
			"description": "基于 Go 语言的极速博客系统",
			"theme":       "default",
			"siteUrl":     "http://localhost:8190",
		}
		for k, v := range options {
			db.Exec("INSERT INTO typecho_options (name, user, value) VALUES (?, 0, ?)", k, v)
		}
		log.Println("Database initialized with default options.")
	}

	// User initialization is now handled by the installer or build script
}

func getSiteInfo(db *sql.DB) SiteInfo {
	return SiteInfo{
		Title:       getOption(db, "title", "我的 Go 博客"),
		Description: getOption(db, "description", "基于 Go 语言的极速博客系统"),
		Keywords:    getOption(db, "keywords", ""),
		Theme:       getOption(db, "theme", "default"),
		SiteUrl:     getOption(db, "siteUrl", "http://localhost:8190"),
		FooterCode:  template.HTML(getOption(db, "footerCode", "")),
	}
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

func getPost(db *sql.DB, cid int) (Post, bool) {
	var p Post
	query := `SELECT t.cid, t.title, t.slug, t.created, t.text, t.commentsNum, t.authorId, u.screenName 
              FROM typecho_contents t 
              LEFT JOIN typecho_users u ON t.authorId = u.uid 
              WHERE t.cid=? AND t.status='publish' AND t.type='post'`
	err := db.QueryRow(query, cid).Scan(&p.Cid, &p.Title, &p.Slug, &p.Created, &p.Text, &p.CommentsNum, &p.AuthorId, &p.Author)
	if err != nil {
		return p, false
	}
	if p.Author == "" {
		p.Author = "admin"
	}
	p.Categories = getPostCategories(db, p.Cid)
	return p, true
}

func getPosts(db *sql.DB, page, pageSize int, search string) ([]Post, int) {
	var total int
	queryCount := `SELECT COUNT(*) FROM typecho_contents t 
                   WHERE t.type='post' AND t.status='publish' 
                   AND t.cid NOT IN (SELECT cid FROM typecho_relationships r JOIN go_category_settings s ON r.mid = s.mid WHERE s.show_on_home = 0 OR s.is_offline = 1)`
	queryList := `SELECT t.cid, t.title, t.slug, t.created, t.text, t.commentsNum, t.authorId, u.screenName 
                  FROM typecho_contents t 
                  LEFT JOIN typecho_users u ON t.authorId = u.uid 
                  WHERE t.type='post' AND t.status='publish'
                  AND t.cid NOT IN (SELECT cid FROM typecho_relationships r JOIN go_category_settings s ON r.mid = s.mid WHERE s.show_on_home = 0 OR s.is_offline = 1)`
	var args []interface{}

	if search != "" {
		filter := " AND (t.title LIKE ? OR t.text LIKE ?)"
		queryCount += filter
		queryList += filter
		args = append(args, "%"+search+"%", "%"+search+"%")
	}

	db.QueryRow(queryCount, args...).Scan(&total)

	queryList += " ORDER BY t.created DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, (page-1)*pageSize)

	var posts []Post
	rows, err := db.Query(queryList, args...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	for rows.Next() {
		var p Post
		rows.Scan(&p.Cid, &p.Title, &p.Slug, &p.Created, &p.Text, &p.CommentsNum, &p.AuthorId, &p.Author)
		if p.Author == "" {
			p.Author = "admin"
		}
		p.Categories = getPostCategories(db, p.Cid)
		posts = append(posts, p)
	}
	return posts, total
}

func getPostsByCategory(db *sql.DB, page, pageSize int, slug string) ([]Post, int) {
	var total int
	db.QueryRow(`
		SELECT COUNT(*) FROM typecho_contents c 
		JOIN typecho_relationships r ON c.cid = r.cid 
		JOIN typecho_metas m ON r.mid = m.mid 
		WHERE c.type='post' AND c.status='publish' AND m.type='category' AND m.slug=?`, slug).Scan(&total)

	offset := (page - 1) * pageSize
	var posts []Post
	rows, err := db.Query(`
		SELECT c.cid, c.title, c.slug, c.created, c.text, c.commentsNum 
		FROM typecho_contents c 
		JOIN typecho_relationships r ON c.cid = r.cid 
		JOIN typecho_metas m ON r.mid = m.mid 
		WHERE c.type='post' AND c.status='publish' AND m.type='category' AND m.slug=? 
		ORDER BY c.created DESC LIMIT ? OFFSET ?`, slug, pageSize, offset)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	for rows.Next() {
		var p Post
		rows.Scan(&p.Cid, &p.Title, &p.Slug, &p.Created, &p.Text, &p.CommentsNum)
		p.Categories = getPostCategories(db, p.Cid)
		posts = append(posts, p)
	}
	return posts, total
}

func getRecentPostsSidebar(db *sql.DB, catSlug string) []Post {
	limit := getOptionInt(db, "recentPostsSize", 15)
	var posts []Post
	var rows *sql.Rows
	var err error

	if catSlug != "" {
		// Only from current category
		rows, err = db.Query(`SELECT t.cid, t.title, t.slug, t.created, t.text, t.commentsNum 
                               FROM typecho_contents t
                               JOIN typecho_relationships r ON t.cid = r.cid
                               JOIN typecho_metas m ON r.mid = m.mid
                               LEFT JOIN go_category_settings s ON m.mid = s.mid
                               WHERE t.type='post' AND t.status='publish' AND m.type='category' AND m.slug=?
                               AND COALESCE(s.is_offline, 0) = 0
                               ORDER BY t.created DESC LIMIT ?`, catSlug, limit)
	} else {
		// Use homepage allow-list logic
		rows, err = db.Query(`SELECT cid, title, slug, created, text, commentsNum 
                              FROM typecho_contents 
                              WHERE type='post' AND status='publish' 
                              AND cid NOT IN (SELECT cid FROM typecho_relationships r JOIN go_category_settings s ON r.mid = s.mid WHERE s.show_on_home = 0 OR s.is_offline = 1)
                              ORDER BY created DESC LIMIT ?`, limit)
	}

	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var p Post
		rows.Scan(&p.Cid, &p.Title, &p.Slug, &p.Created, &p.Text, &p.CommentsNum)
		posts = append(posts, p)
	}
	return posts
}

func getPostCategories(db *sql.DB, cid int) []Category {
	var cats []Category
	rows, err := db.Query(`
		SELECT m.mid, m.name, m.slug 
		FROM typecho_metas m 
		JOIN typecho_relationships r ON m.mid = r.mid 
		WHERE r.cid = ? AND m.type = 'category'`, cid)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var cat Category
		rows.Scan(&cat.Mid, &cat.Name, &cat.Slug)
		cats = append(cats, cat)
	}
	return cats
}

func getCategories(db *sql.DB) []Category {
	var cats []Category
	rows, _ := db.Query(`SELECT m.mid, m.name, m.slug 
                       FROM typecho_metas m
                       LEFT JOIN go_category_settings s ON m.mid = s.mid
                       WHERE m.type='category' AND COALESCE(s.is_offline, 0) = 0
                       ORDER BY m."order" ASC, m.mid ASC`)
	defer rows.Close()
	for rows.Next() {
		var cat Category
		rows.Scan(&cat.Mid, &cat.Name, &cat.Slug)
		cats = append(cats, cat)
	}
	return cats
}

func getRecentComments(db *sql.DB, catSlug string) []Comment {
	limit := getOptionInt(db, "recentCommentsSize", 10)
	var comms []Comment
	var rows *sql.Rows
	var err error

	if catSlug != "" {
		// Only from posts in this category
		rows, err = db.Query(`SELECT c.coid, c.cid, c.author, c.text, c.created 
                               FROM typecho_comments c
                               JOIN typecho_relationships r ON c.cid = r.cid
                               JOIN typecho_metas m ON r.mid = m.mid
                               WHERE c.status='approved' AND c.type='comment' AND m.type='category' AND m.slug=?
                               ORDER BY c.created DESC LIMIT ?`, catSlug, limit)
	} else {
		// Publicly visible posts only (homepage allowed & not offline)
		rows, err = db.Query(`SELECT coid, cid, author, text, created 
                              FROM typecho_comments 
                              WHERE status='approved' AND type='comment'
                              AND cid NOT IN (SELECT cid FROM typecho_relationships r JOIN go_category_settings s ON r.mid = s.mid WHERE s.show_on_home = 0 OR s.is_offline = 1)
                              ORDER BY created DESC LIMIT ?`, limit)
	}

	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var comm Comment
		rows.Scan(&comm.Coid, &comm.Cid, &comm.Author, &comm.Text, &comm.Created)

		runes := []rune(comm.Text)
		if len(runes) > 35 {
			comm.Text = string(runes[:35]) + "..."
		}
		comms = append(comms, comm)
	}
	return comms
}

func getPostTags(db *sql.DB, cid int) []Tag {
	var tags []Tag
	rows, err := db.Query(`
		SELECT m.name, m.slug 
		FROM typecho_metas m 
		JOIN typecho_relationships r ON m.mid = r.mid 
		WHERE r.cid = ? AND m.type = 'tag'`, cid)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var t Tag
		rows.Scan(&t.Name, &t.Slug)
		tags = append(tags, t)
	}
	return tags
}

func getPostComments(db *sql.DB, cid int) []Comment {
	var comms []Comment
	rows, err := db.Query(`
		SELECT coid, author, text, created 
		FROM typecho_comments 
		WHERE cid = ? AND status = 'approved' AND type = 'comment' 
		ORDER BY created ASC`, cid)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var c Comment
		rows.Scan(&c.Coid, &c.Author, &c.Text, &c.Created)
		comms = append(comms, c)
	}
	return comms
}

func getPrevNextPosts(db *sql.DB, created int64) (*Post, *Post) {
	var prev, next *Post

	// Prev
	var p Post
	err := db.QueryRow(`SELECT cid, title FROM typecho_contents 
                         WHERE type='post' AND status='publish' AND created < ? 
                         AND cid NOT IN (SELECT cid FROM typecho_relationships r JOIN go_category_settings s ON r.mid = s.mid WHERE s.is_offline = 1)
                         ORDER BY created DESC LIMIT 1`, created).Scan(&p.Cid, &p.Title)
	if err == nil {
		prev = &p
	}

	// Next
	var n Post
	err = db.QueryRow(`SELECT cid, title FROM typecho_contents 
                        WHERE type='post' AND status='publish' AND created > ? 
                        AND cid NOT IN (SELECT cid FROM typecho_relationships r JOIN go_category_settings s ON r.mid = s.mid WHERE s.is_offline = 1)
                        ORDER BY created ASC LIMIT 1`, created).Scan(&n.Cid, &n.Title)
	if err == nil {
		next = &n
	}

	return prev, next
}

func checkSpamAI(words string, apiKey string, apiUrl string, model string) int {
	if apiKey == "" || apiUrl == "" || model == "" {
		return 0 // Disable check if configuration is missing
	}

	systemPrompt := "You are an assistant for detecting spam, advertisements, meaningless text, and malicious content such as SQL injection or XSS. Score user input from 0 to 9, where 0 means safe (e.g., programming or server-related), 5 means suspicious, and 9 means confirmed spam, ads, attacks, or nonsense like \"asdf\", \"12345\", \"aaaa\". If the input is not in English or Chinese, score it as 9. Only return a single integer (0–9) with no explanation."

	requestData := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": words},
		},
		"max_tokens":  1,
		"temperature": 0.1,
	}

	jsonData, _ := json.Marshal(requestData)
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("POST", apiUrl, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return 0 // Fallback to safe on error
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && len(result.Choices) > 0 {
			content := strings.TrimSpace(result.Choices[0].Message.Content)
			// Handle cases where the model might start with a thinking tag
			if strings.HasPrefix(content, "<") || strings.Contains(content, "think") {
				return 0 // Fallback to safe if it's a reasoning model
			}
			var score int
			fmt.Sscanf(content, "%d", &score)
			return score
		}
	}

	return 0
}
