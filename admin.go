package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
	_ "modernc.org/sqlite"
)

var (
	isBackingUp           bool
	backupMutex           sync.Mutex
	backupLastResult      string
	backupLastResultIsErr bool
	systemTimeLocation    = time.Local
	skinThemeNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	skinColorPattern      = regexp.MustCompile(`(?i)^(#[0-9a-f]{3}|#[0-9a-f]{6}|#[0-9a-f]{8}|rgba?\([0-9.,%\s/+-]+\)|hsla?\([0-9.,%\s/+-]+\)|transparent|inherit|initial|unset|currentColor|[a-z]+)$`)
	skinLengthPattern     = regexp.MustCompile(`(?i)^(0|[0-9]+(?:\.[0-9]+)?)(px|rem|em|vw|vh|%)?$`)
	adminAttachmentRe     = regexp.MustCompile(`(src|href)="https?://[^/]+(/[^"]+)"`)
	backupTimePattern     = regexp.MustCompile(`^\d{2}:\d{2}$`)
)

type backupEntry struct {
	Name    string
	Size    string
	Bytes   int64
	Time    string
	RawTime time.Time
	Storage string
}

type backupStorageConfig struct {
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	Prefix         string
	ForcePathStyle bool
}

type backupScheduleConfig struct {
	Enabled         bool
	DailyTime       string
	RetentionCount  int
	Weekdays        []int
	WeekdayLabels   string
	LastRunDate     string
	LastAttemptDate string
}

type s3ListBucketResult struct {
	Contents []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		Size         int64  `xml:"Size"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

type s3ErrorResult struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func adminFixAttachmentLinks(htmlContent string) string {
	return adminAttachmentRe.ReplaceAllStringFunc(htmlContent, func(match string) string {
		sub := adminAttachmentRe.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		attr := sub[1]
		path := sub[2]

		purePath := path
		if idx := strings.Index(path, "?"); idx != -1 {
			purePath = path[:idx]
		}

		lowerPath := strings.ToLower(purePath)
		isImg := strings.HasSuffix(lowerPath, ".jpg") ||
			strings.HasSuffix(lowerPath, ".jpeg") ||
			strings.HasSuffix(lowerPath, ".png") ||
			strings.HasSuffix(lowerPath, ".gif") ||
			strings.HasSuffix(lowerPath, ".webp") ||
			strings.HasSuffix(lowerPath, ".svg")

		if strings.HasPrefix(path, "/usr/") || isImg {
			return fmt.Sprintf("%s=\"%s\"", attr, path)
		}

		return match
	})
}

func adminPreviewTitle(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "无标题"
	}
	return fmt.Sprintf(`<h1 class="admin-preview-title">%s</h1>`, template.HTMLEscapeString(title))
}

func adminRenderPostPreview(mdRenderer goldmark.Markdown, title, text string) (string, error) {
	content := strings.TrimPrefix(text, "<!--markdown-->")
	parts := strings.Split(content, "<!--more-->")
	excerpt := strings.TrimSpace(parts[0])
	if excerpt == "" {
		return adminPreviewTitle(title) + `<p>暂无文章内容</p>`, nil
	}

	var buf bytes.Buffer
	if err := mdRenderer.Convert([]byte(excerpt), &buf); err != nil {
		return "", err
	}

	return adminPreviewTitle(title) + adminFixAttachmentLinks(buf.String()), nil
}

func adminRenderPostContent(mdRenderer goldmark.Markdown, title, text string) (string, error) {
	content := strings.TrimSpace(strings.TrimPrefix(text, "<!--markdown-->"))
	if content == "" {
		return adminPreviewTitle(title) + `<p>暂无文章内容</p>`, nil
	}

	var buf bytes.Buffer
	if err := mdRenderer.Convert([]byte(content), &buf); err != nil {
		return "", err
	}

	return adminPreviewTitle(title) + adminFixAttachmentLinks(buf.String()), nil
}

func getBackupStorageConfig(db *sql.DB) backupStorageConfig {
	return backupStorageConfig{
		Endpoint:       strings.TrimSpace(getOption(db, "backupS3Endpoint", "")),
		Region:         strings.TrimSpace(getOption(db, "backupS3Region", "")),
		Bucket:         strings.TrimSpace(getOption(db, "backupS3Bucket", "")),
		AccessKey:      strings.TrimSpace(getOption(db, "backupS3AccessKey", "")),
		SecretKey:      strings.TrimSpace(getOption(db, "backupS3SecretKey", "")),
		Prefix:         strings.TrimSpace(getOption(db, "backupS3Prefix", "")),
		ForcePathStyle: getOption(db, "backupS3ForcePathStyle", "0") == "1",
	}
}

func getBackupStorageDraftConfig(db *sql.DB) backupStorageConfig {
	activeCfg := getBackupStorageConfig(db)
	activeForcePathStyle := "0"
	if activeCfg.ForcePathStyle {
		activeForcePathStyle = "1"
	}

	return backupStorageConfig{
		Endpoint:       strings.TrimSpace(getOption(db, "backupS3DraftEndpoint", activeCfg.Endpoint)),
		Region:         strings.TrimSpace(getOption(db, "backupS3DraftRegion", activeCfg.Region)),
		Bucket:         strings.TrimSpace(getOption(db, "backupS3DraftBucket", activeCfg.Bucket)),
		AccessKey:      strings.TrimSpace(getOption(db, "backupS3DraftAccessKey", activeCfg.AccessKey)),
		SecretKey:      strings.TrimSpace(getOption(db, "backupS3DraftSecretKey", activeCfg.SecretKey)),
		Prefix:         strings.TrimSpace(getOption(db, "backupS3DraftPrefix", activeCfg.Prefix)),
		ForcePathStyle: getOption(db, "backupS3DraftForcePathStyle", activeForcePathStyle) == "1",
	}
}

func (cfg backupStorageConfig) Enabled() bool {
	return cfg.Endpoint != "" && cfg.Region != "" && cfg.Bucket != "" && cfg.AccessKey != "" && cfg.SecretKey != ""
}

func (cfg backupStorageConfig) HasAnyValue() bool {
	return cfg.Endpoint != "" || cfg.Region != "" || cfg.Bucket != "" || cfg.AccessKey != "" || cfg.SecretKey != "" || cfg.Prefix != "" || cfg.ForcePathStyle
}

func (cfg backupStorageConfig) RegionOrDefault() string {
	return strings.TrimSpace(cfg.Region)
}

func (cfg backupStorageConfig) NormalizedPrefix() string {
	return strings.Trim(strings.TrimSpace(cfg.Prefix), "/")
}

func (cfg backupStorageConfig) ObjectKey(filename string) string {
	prefix := cfg.NormalizedPrefix()
	if prefix == "" {
		return filename
	}
	return prefix + "/" + filename
}

func (cfg backupStorageConfig) Summary() string {
	if cfg.Enabled() {
		if prefix := cfg.NormalizedPrefix(); prefix != "" {
			return fmt.Sprintf("S3 兼容存储：%s / %s（前缀：%s/）", cfg.Endpoint, cfg.Bucket, prefix)
		}
		return fmt.Sprintf("S3 兼容存储：%s / %s", cfg.Endpoint, cfg.Bucket)
	}
	if cfg.HasAnyValue() {
		return "S3 配置未填写完整，当前仍保存到服务器本地 backups/ 目录"
	}
	return "当前默认保存到服务器本地 backups/ 目录"
}

func getGoOnlyOption(db *sql.DB, name string, defaultValue string) string {
	var val string
	err := db.QueryRow("SELECT value FROM go_options WHERE name=?", name).Scan(&val)
	if err == nil {
		return val
	}
	return defaultValue
}

func getGoOnlyOptionInt(db *sql.DB, name string, defaultValue int) int {
	val := strings.TrimSpace(getGoOnlyOption(db, name, ""))
	if val == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return i
}

func setGoOnlyOption(db *sql.DB, name string, value string) {
	_, err := db.Exec("INSERT INTO go_options (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", name, value)
	if err != nil {
		log.Printf("Error setting go-only option %s: %v", name, err)
	}
}

func normalizeBackupScheduleTime(value string) string {
	value = strings.TrimSpace(value)
	if !backupTimePattern.MatchString(value) {
		return "03:00"
	}
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return "03:00"
	}
	return parsed.Format("15:04")
}

func isValidBackupScheduleTime(value string) bool {
	return normalizeBackupScheduleTime(value) == strings.TrimSpace(value)
}

func buildTimeSelectOptions(start, end int, selected string) []map[string]interface{} {
	options := make([]map[string]interface{}, 0, end-start+1)
	for i := start; i <= end; i++ {
		value := fmt.Sprintf("%02d", i)
		options = append(options, map[string]interface{}{
			"Value":    value,
			"Label":    value,
			"Selected": value == selected,
		})
	}
	return options
}

func splitBackupScheduleTime(value string) (string, string) {
	value = normalizeBackupScheduleTime(value)
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "03", "00"
	}
	return parts[0], parts[1]
}

func normalizeBackupScheduleWeekdays(values []string) []int {
	allowed := map[int]bool{
		0: true,
		1: true,
		2: true,
		3: true,
		4: true,
		5: true,
		6: true,
	}
	seen := make(map[int]bool)
	result := make([]int, 0, 7)
	for _, raw := range values {
		day, err := strconv.Atoi(strings.TrimSpace(raw))
		if day == 7 {
			day = 0
		}
		if err != nil || !allowed[day] || seen[day] {
			continue
		}
		seen[day] = true
		result = append(result, day)
	}
	sortBackupScheduleWeekdays(result)
	if len(result) == 0 {
		return []int{1, 2, 3, 4, 5, 6, 0}
	}
	return result
}

func backupScheduleWeekdayOptions(selected []int) []map[string]interface{} {
	contains := func(target int) bool {
		for _, day := range selected {
			if day == target {
				return true
			}
		}
		return false
	}
	return []map[string]interface{}{
		{"Value": 1, "Label": "周一", "Checked": contains(1)},
		{"Value": 2, "Label": "周二", "Checked": contains(2)},
		{"Value": 3, "Label": "周三", "Checked": contains(3)},
		{"Value": 4, "Label": "周四", "Checked": contains(4)},
		{"Value": 5, "Label": "周五", "Checked": contains(5)},
		{"Value": 6, "Label": "周六", "Checked": contains(6)},
		{"Value": 0, "Label": "周日", "Checked": contains(0)},
	}
}

func formatBackupScheduleWeekdays(days []int) string {
	labelMap := map[int]string{
		0: "周日",
		1: "周一",
		2: "周二",
		3: "周三",
		4: "周四",
		5: "周五",
		6: "周六",
	}
	parts := make([]string, 0, len(days))
	for _, day := range days {
		if label, ok := labelMap[day]; ok {
			parts = append(parts, label)
		}
	}
	if len(parts) == 0 {
		return "周一至周日"
	}
	if len(parts) == 7 {
		return "周一至周日"
	}
	return strings.Join(parts, "、")
}

func sortBackupScheduleWeekdays(days []int) {
	order := map[int]int{
		1: 1,
		2: 2,
		3: 3,
		4: 4,
		5: 5,
		6: 6,
		0: 7,
	}
	sort.Slice(days, func(i, j int) bool {
		return order[days[i]] < order[days[j]]
	})
}

func weekdayToScheduleValue(day time.Weekday) int {
	return int(day)
}

func containsBackupScheduleWeekday(days []int, target int) bool {
	for _, day := range days {
		if day == target {
			return true
		}
	}
	return false
}

func normalizeBackupScheduleLastRun(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	for _, layout := range []string{
		"2006-01-02 15:04",
		"2006-01-02 15:04:05",
		"2006-01-02",
		time.RFC3339,
	} {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			if layout == "2006-01-02" {
				return parsed.Format("2006-01-02 00:00")
			}
			return parsed.Format("2006-01-02 15:04")
		}
	}

	return value
}

func getBackupScheduleConfig(db *sql.DB) backupScheduleConfig {
	retentionCount := getGoOnlyOptionInt(db, "backupScheduleRetentionCount", 7)
	if retentionCount < 1 {
		retentionCount = 7
	}
	if retentionCount > 365 {
		retentionCount = 365
	}

	lastRunDate := strings.TrimSpace(getGoOnlyOption(db, "backupScheduleLastRunDate", ""))
	lastRunDate = normalizeBackupScheduleLastRun(lastRunDate)

	lastAttemptDate := strings.TrimSpace(getGoOnlyOption(db, "backupScheduleLastAttemptDate", ""))
	if lastAttemptDate != "" {
		if _, err := time.Parse("2006-01-02", lastAttemptDate); err != nil {
			lastAttemptDate = ""
		}
	}

	weekdayValues := normalizeBackupScheduleWeekdays(strings.Split(getGoOnlyOption(db, "backupScheduleWeekdays", ""), ","))

	return backupScheduleConfig{
		Enabled:         getGoOnlyOption(db, "backupScheduleEnabled", "0") == "1",
		DailyTime:       normalizeBackupScheduleTime(getGoOnlyOption(db, "backupScheduleTime", "03:00")),
		RetentionCount:  retentionCount,
		Weekdays:        weekdayValues,
		WeekdayLabels:   formatBackupScheduleWeekdays(weekdayValues),
		LastRunDate:     lastRunDate,
		LastAttemptDate: lastAttemptDate,
	}
}

func (cfg backupScheduleConfig) Summary() string {
	if !cfg.Enabled {
		return "未开启定时备份，当前仍可按需手动创建备份。"
	}
	return fmt.Sprintf("已开启，在 %s 的 %s 自动备份，保留最近 %d 个备份文件。", cfg.WeekdayLabels, cfg.DailyTime, cfg.RetentionCount)
}

func formatBackupSize(size int64) string {
	return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
}

func listLocalBackupEntries() ([]backupEntry, error) {
	if err := os.MkdirAll("backups", 0755); err != nil {
		return nil, err
	}

	files, err := os.ReadDir("backups")
	if err != nil {
		return nil, err
	}

	backups := make([]backupEntry, 0, len(files))
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".tar.gz") {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupEntry{
			Name:    f.Name(),
			Size:    formatBackupSize(info.Size()),
			Bytes:   info.Size(),
			Time:    info.ModTime().Format("2006-01-02 15:04:05"),
			RawTime: info.ModTime(),
			Storage: "本地",
		})
	}
	return backups, nil
}

func escapeS3Path(path string) string {
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func awsEncodeQueryComponent(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}

func buildAWSCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(values))
	for _, key := range keys {
		vals := append([]string(nil), values[key]...)
		sort.Strings(vals)
		if len(vals) == 0 {
			parts = append(parts, awsEncodeQueryComponent(key)+"=")
			continue
		}
		for _, val := range vals {
			parts = append(parts, awsEncodeQueryComponent(key)+"="+awsEncodeQueryComponent(val))
		}
	}
	return strings.Join(parts, "&")
}

func sha256HexString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sha256HexFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func hmacSHA256Bytes(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func buildS3RequestTarget(cfg backupStorageConfig, objectKey string, query url.Values) (string, string, string, string, error) {
	endpointURL, err := url.Parse(cfg.Endpoint)
	if err != nil || endpointURL.Scheme == "" || endpointURL.Host == "" {
		return "", "", "", "", fmt.Errorf("S3 Endpoint 无效")
	}

	host := endpointURL.Host
	basePath := strings.TrimSuffix(endpointURL.EscapedPath(), "/")
	canonicalURI := basePath
	if cfg.ForcePathStyle {
		canonicalURI += "/" + url.PathEscape(cfg.Bucket)
		if objectKey != "" {
			canonicalURI += "/" + escapeS3Path(objectKey)
		}
	} else {
		host = cfg.Bucket + "." + endpointURL.Host
		if objectKey != "" {
			if canonicalURI == "" || canonicalURI == "/" {
				canonicalURI = "/" + escapeS3Path(objectKey)
			} else {
				canonicalURI += "/" + escapeS3Path(objectKey)
			}
		}
	}

	if canonicalURI == "" {
		canonicalURI = "/"
	}
	if !strings.HasPrefix(canonicalURI, "/") {
		canonicalURI = "/" + canonicalURI
	}

	canonicalQuery := buildAWSCanonicalQuery(query)
	requestURL := endpointURL.Scheme + "://" + host + canonicalURI
	if canonicalQuery != "" {
		requestURL += "?" + canonicalQuery
	}

	return requestURL, host, canonicalURI, canonicalQuery, nil
}

func newS3SignedRequest(cfg backupStorageConfig, method, objectKey string, query url.Values, payloadHash string, body io.Reader) (*http.Request, error) {
	if payloadHash == "" {
		payloadHash = sha256HexString("")
	}

	requestURL, host, canonicalURI, canonicalQuery, err := buildS3RequestTarget(cfg, objectKey, query)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	shortDate := now.Format("20060102")
	region := cfg.RegionOrDefault()
	if region == "" {
		return nil, fmt.Errorf("S3 Region 未填写")
	}
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := shortDate + "/" + region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256HexString(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256Bytes([]byte("AWS4"+cfg.SecretKey), shortDate)
	kRegion := hmacSHA256Bytes(kDate, region)
	kService := hmacSHA256Bytes(kRegion, "s3")
	kSigning := hmacSHA256Bytes(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256Bytes(kSigning, stringToSign))

	req, err := http.NewRequest(method, requestURL, body)
	if err != nil {
		return nil, err
	}

	req.Host = host
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cfg.AccessKey+"/"+credentialScope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/gzip")
	}

	return req, nil
}

func readS3Error(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if len(body) > 0 {
		var apiErr s3ErrorResult
		if err := xml.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.Message) != "" {
			return formatS3UserError(strings.TrimSpace(apiErr.Message))
		}
		return formatS3UserError(strings.TrimSpace(string(body)))
	}
	return formatS3UserError(fmt.Sprintf("服务返回状态码 %d", resp.StatusCode))
}

func formatS3UserError(detail string) error {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return fmt.Errorf("S3 参数或服务异常，请检查 S3 参数或稍后重试。")
	}
	return fmt.Errorf("S3 参数或服务异常，错误信息：%s", detail)
}

func parseS3ObjectTime(value string) time.Time {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05Z"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.Local()
		}
	}
	return time.Time{}
}

func listS3BackupEntries(cfg backupStorageConfig) ([]backupEntry, error) {
	if !cfg.Enabled() {
		return nil, nil
	}

	client := &http.Client{Timeout: 90 * time.Second}
	prefix := cfg.NormalizedPrefix()
	listPrefix := prefix
	if listPrefix != "" {
		listPrefix += "/"
	}

	var backups []backupEntry
	var continuation string
	for {
		query := url.Values{}
		query.Set("list-type", "2")
		if listPrefix != "" {
			query.Set("prefix", listPrefix)
		}
		if continuation != "" {
			query.Set("continuation-token", continuation)
		}

		req, err := newS3SignedRequest(cfg, http.MethodGet, "", query, sha256HexString(""), nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, formatS3UserError(err.Error())
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err = readS3Error(resp)
			resp.Body.Close()
			return nil, err
		}

		var result s3ListBucketResult
		err = xml.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return nil, formatS3UserError("S3 列表返回内容解析失败")
		}

		for _, item := range result.Contents {
			name := strings.TrimPrefix(item.Key, listPrefix)
			if name == "" || strings.Contains(name, "/") || !strings.HasSuffix(name, ".tar.gz") {
				continue
			}

			modTime := parseS3ObjectTime(item.LastModified)
			displayTime := item.LastModified
			if !modTime.IsZero() {
				displayTime = modTime.Format("2006-01-02 15:04:05")
			}
			backups = append(backups, backupEntry{
				Name:    name,
				Size:    formatBackupSize(item.Size),
				Bytes:   item.Size,
				Time:    displayTime,
				RawTime: modTime,
				Storage: "S3",
			})
		}

		if !result.IsTruncated || strings.TrimSpace(result.NextContinuationToken) == "" {
			break
		}
		continuation = strings.TrimSpace(result.NextContinuationToken)
	}

	return backups, nil
}

func uploadBackupToS3(cfg backupStorageConfig, localPath, filename string) error {
	payloadHash, err := sha256HexFile(localPath)
	if err != nil {
		return err
	}

	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}

	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()

	req, err := newS3SignedRequest(cfg, http.MethodPut, cfg.ObjectKey(filename), nil, payloadHash, file)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Length", strconv.FormatInt(info.Size(), 10))

	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return formatS3UserError(err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readS3Error(resp)
	}
	return nil
}

func deleteBackupFromS3(cfg backupStorageConfig, filename string) error {
	req, err := newS3SignedRequest(cfg, http.MethodDelete, cfg.ObjectKey(filename), nil, sha256HexString(""), nil)
	if err != nil {
		return err
	}

	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return formatS3UserError(err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readS3Error(resp)
	}
	return nil
}

func testS3Credentials(cfg backupStorageConfig) error {
	if !cfg.Enabled() {
		return fmt.Errorf("请先填写完整的 S3 Endpoint、Region、Bucket、Access Key 和 Secret Key。")
	}

	query := url.Values{}
	query.Set("list-type", "2")
	query.Set("max-keys", "1")
	if prefix := cfg.NormalizedPrefix(); prefix != "" {
		query.Set("prefix", prefix+"/")
	}

	req, err := newS3SignedRequest(cfg, http.MethodGet, "", query, sha256HexString(""), nil)
	if err != nil {
		return err
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return formatS3UserError(err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readS3Error(resp)
	}

	var result s3ListBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return formatS3UserError("S3 返回内容解析失败")
	}

	return nil
}

func setBackupResult(message string, isErr bool) {
	backupMutex.Lock()
	backupLastResult = message
	backupLastResultIsErr = isErr
	backupMutex.Unlock()
}

func sortBackupEntriesByTimeDesc(backups []backupEntry) {
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].RawTime.Equal(backups[j].RawTime) {
			return backups[i].Name > backups[j].Name
		}
		return backups[i].RawTime.After(backups[j].RawTime)
	})
}

func pruneLocalBackups(keepCount int) (int, error) {
	if keepCount < 1 {
		return 0, nil
	}

	backups, err := listLocalBackupEntries()
	if err != nil {
		return 0, err
	}
	if len(backups) <= keepCount {
		return 0, nil
	}

	sortBackupEntriesByTimeDesc(backups)
	removed := 0
	for _, item := range backups[keepCount:] {
		if err := os.Remove(filepath.Join("backups", item.Name)); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		removed++
	}

	return removed, nil
}

func pruneS3Backups(cfg backupStorageConfig, keepCount int) (int, error) {
	if keepCount < 1 {
		return 0, nil
	}

	backups, err := listS3BackupEntries(cfg)
	if err != nil {
		return 0, err
	}
	if len(backups) <= keepCount {
		return 0, nil
	}

	sortBackupEntriesByTimeDesc(backups)
	removed := 0
	for _, item := range backups[keepCount:] {
		if err := deleteBackupFromS3(cfg, item.Name); err != nil {
			return removed, err
		}
		removed++
	}

	return removed, nil
}

func createBackupArchive(db *sql.DB) (string, string, error) {
	if err := os.MkdirAll("backups", 0755); err != nil {
		return "", "", err
	}

	filename := fmt.Sprintf("backup_%s.tar.gz", time.Now().Format("20060102_150405"))
	targetPath := filepath.Join("backups", filename)

	// 确保 WAL 日志中的数据全部合并到主数据库文件，保证备份完整性
	db.Exec("PRAGMA wal_checkpoint(FULL)")

	cmd := exec.Command("tar", "-czf", targetPath, "blog.sqlite", "usr")
	if err := cmd.Run(); err != nil {
		return "", "", err
	}

	return targetPath, filename, nil
}

func runBackupJob(db *sql.DB, trigger string) error {
	backupMutex.Lock()
	if isBackingUp {
		backupMutex.Unlock()
		return fmt.Errorf("备份任务正在进行中")
	}
	isBackingUp = true
	backupLastResult = ""
	backupLastResultIsErr = false
	backupMutex.Unlock()

	if trigger == "scheduled" {
		setGoOnlyOption(db, "backupScheduleLastAttemptDate", time.Now().Format("2006-01-02"))
	}

	go func() {
		defer func() {
			backupMutex.Lock()
			isBackingUp = false
			backupMutex.Unlock()
		}()

		targetPath, filename, err := createBackupArchive(db)
		if err != nil {
			if os.IsPermission(err) {
				setBackupResult("备份目录创建失败", true)
			} else {
				setBackupResult("备份创建失败", true)
			}
			log.Printf("Backup job failed during archive creation [%s]: %v", trigger, err)
			return
		}

		storageCfg := getBackupStorageConfig(db)
		resultMessage := "备份任务已完成"
		resultStorage := "local"

		if storageCfg.Enabled() {
			if err := uploadBackupToS3(storageCfg, targetPath, filename); err != nil {
				setBackupResult(fmt.Sprintf("S3 上传失败，备份已保留在本地 backups/%s", filename), true)
				log.Printf("Backup job upload failed [%s]: %v", trigger, err)
				return
			}
			if err := os.Remove(targetPath); err != nil {
				setBackupResult(fmt.Sprintf("备份已上传到 S3，但本地文件清理失败：backups/%s", filename), false)
				log.Printf("Backup job cleanup failed [%s]: %v", trigger, err)
				return
			}
			resultStorage = "s3"
			resultMessage = fmt.Sprintf("备份已上传到 S3 存储桶 %s", storageCfg.Bucket)
			log.Printf("Backup job uploaded to S3 [%s]: %s", trigger, storageCfg.ObjectKey(filename))
		} else if storageCfg.HasAnyValue() {
			resultMessage = "S3 配置未填写完整，备份已保存到本地 backups/ 目录"
			log.Printf("Backup job created locally with incomplete S3 config [%s]: %s", trigger, targetPath)
		} else {
			log.Printf("Backup job created locally [%s]: %s", trigger, targetPath)
		}

		if trigger == "scheduled" {
			scheduleCfg := getBackupScheduleConfig(db)
			retentionMessage := ""
			if scheduleCfg.Enabled {
				var removed int
				if resultStorage == "s3" {
					removed, err = pruneS3Backups(storageCfg, scheduleCfg.RetentionCount)
				} else {
					removed, err = pruneLocalBackups(scheduleCfg.RetentionCount)
				}
				if err != nil {
					setGoOnlyOption(db, "backupScheduleLastRunDate", time.Now().Format("2006-01-02 15:04"))
					setBackupResult("每日定时备份已完成，但旧备份清理失败。", true)
					log.Printf("Scheduled backup retention failed: %v", err)
					return
				}
				if removed > 0 {
					retentionMessage = fmt.Sprintf("，并清理了 %d 个旧备份", removed)
				}
			}

			setGoOnlyOption(db, "backupScheduleLastRunDate", time.Now().Format("2006-01-02 15:04"))
			if resultStorage == "s3" {
				setBackupResult(fmt.Sprintf("每日定时备份已上传到 S3 存储桶 %s%s", storageCfg.Bucket, retentionMessage), false)
			} else if resultMessage != "备份任务已完成" {
				setBackupResult("每日定时备份已完成，"+resultMessage+retentionMessage, false)
			} else {
				setBackupResult("每日定时备份已完成"+retentionMessage, false)
			}
			return
		}

		setBackupResult(resultMessage, false)
	}()

	return nil
}

func checkAndRunScheduledBackup(db *sql.DB) {
	cfg := getBackupScheduleConfig(db)
	if !cfg.Enabled {
		return
	}

	today := time.Now().Format("2006-01-02")
	if cfg.LastAttemptDate == today {
		return
	}

	parsed, err := time.Parse("15:04", cfg.DailyTime)
	if err != nil {
		return
	}

	now := time.Now()
	if !containsBackupScheduleWeekday(cfg.Weekdays, weekdayToScheduleValue(now.Weekday())) {
		return
	}
	scheduledAt := time.Date(now.Year(), now.Month(), now.Day(), parsed.Hour(), parsed.Minute(), 0, 0, now.Location())
	if now.Before(scheduledAt) {
		return
	}

	if err := runBackupJob(db, "scheduled"); err != nil {
		if err.Error() != "备份任务正在进行中" {
			log.Printf("Scheduled backup start failed: %v", err)
		}
	}
}

func startBackupScheduleWorker(db *sql.DB) {
	checkAndRunScheduledBackup(db)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		checkAndRunScheduledBackup(db)
	}
}

func getBackupDashboardInfo(db *sql.DB) (float64, string) {
	localBackups, _ := listLocalBackupEntries()
	var totalBytes int64
	var latestBackup backupEntry
	for _, item := range localBackups {
		totalBytes += item.Bytes
		if item.RawTime.After(latestBackup.RawTime) {
			latestBackup = item
		}
	}

	storageCfg := getBackupStorageConfig(db)
	remoteBackups, err := listS3BackupEntries(storageCfg)
	if err == nil {
		for _, item := range remoteBackups {
			totalBytes += item.Bytes
			if item.RawTime.After(latestBackup.RawTime) {
				latestBackup = item
			}
		}
	}

	latestBackupTime := "暂无成功备份"
	if !latestBackup.RawTime.IsZero() {
		latestBackupTime = latestBackup.RawTime.Format("2006-01-02 15:04:05") + " / " + latestBackup.Storage
	} else if lastRunDate := getBackupScheduleConfig(db).LastRunDate; lastRunDate != "" {
		latestBackupTime = lastRunDate
	}

	return float64(totalBytes) / (1024 * 1024), latestBackupTime
}

type dashboardStorageInfo struct {
	UploadSize     string
	BackupSize     string
	LastBackupTime string
}

var dashboardStorageInfoCache = struct {
	sync.Mutex
	UpdatedAt time.Time
	Data      dashboardStorageInfo
}{}

func getCachedDashboardStorageInfo(db *sql.DB) dashboardStorageInfo {
	dashboardStorageInfoCache.Lock()
	if !dashboardStorageInfoCache.UpdatedAt.IsZero() && time.Since(dashboardStorageInfoCache.UpdatedAt) < time.Minute {
		data := dashboardStorageInfoCache.Data
		dashboardStorageInfoCache.Unlock()
		return data
	}
	dashboardStorageInfoCache.Unlock()

	var uploadBytes int64
	filepath.Walk("usr/uploads", func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			uploadBytes += info.Size()
		}
		return nil
	})
	backupUsageMB, lastBackupTime := getBackupDashboardInfo(db)
	data := dashboardStorageInfo{
		UploadSize:     fmt.Sprintf("%.2f MB", float64(uploadBytes)/(1024*1024)),
		BackupSize:     fmt.Sprintf("%.2f MB", backupUsageMB),
		LastBackupTime: lastBackupTime,
	}

	dashboardStorageInfoCache.Lock()
	dashboardStorageInfoCache.Data = data
	dashboardStorageInfoCache.UpdatedAt = time.Now()
	dashboardStorageInfoCache.Unlock()
	return data
}

type cloudflareAccessLogItem struct {
	Datetime string `json:"datetime"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
}

type cfBlockedIPRule struct {
	IP     string `json:"ip"`
	RuleID string `json:"rule_id"`
}

type SkinConfig struct {
	Theme               string
	ThemeBase           string
	PrimaryColor        string
	PrimaryHover        string
	SuccessColor        string
	TextPrimary         string
	TextSecondary       string
	TextMuted           string
	BgPrimary           string
	BgSecondary         string
	BgAccent            string
	BorderLight         string
	HeaderBg            string
	ThemeBtnHoverBg     string
	ThemeBtnActiveBg    string
	Radius              string
	LayoutContainerMax  string
	LayoutContainerPad  string
	LayoutColumnGap     string
	LayoutPagePadding   string
	LayoutPostPadding   string
	LayoutWidgetPadding string
}

type adminPasskey struct {
	ID             int
	CredentialID   string
	Name           string
	CreatedAt      int64
	LastUsedAt     int64
	CreatedAtText  string
	LastUsedAtText string
}

type adminWebAuthnUser struct {
	UID         int
	Name        string
	DisplayName string
	Credentials []webauthnlib.Credential
}

func (u adminWebAuthnUser) WebAuthnID() []byte {
	return []byte(strconv.Itoa(u.UID))
}

func (u adminWebAuthnUser) WebAuthnName() string {
	return u.Name
}

func (u adminWebAuthnUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.Name
}

func (u adminWebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u adminWebAuthnUser) WebAuthnCredentials() []webauthnlib.Credential {
	return u.Credentials
}

type adminWebAuthnSession struct {
	Username  string
	Session   webauthnlib.SessionData
	ExpiresAt int64
}

type adminWebAuthnSessionStore struct {
	mu       sync.Mutex
	sessions map[string]adminWebAuthnSession
}

func newAdminWebAuthnSessionStore() *adminWebAuthnSessionStore {
	return &adminWebAuthnSessionStore{sessions: make(map[string]adminWebAuthnSession)}
}

func (s *adminWebAuthnSessionStore) put(username string, session *webauthnlib.SessionData) string {
	if session == nil {
		return ""
	}
	id := uuid.New().String()
	now := time.Now().Unix()
	s.mu.Lock()
	for key, item := range s.sessions {
		if item.ExpiresAt <= now {
			delete(s.sessions, key)
		}
	}
	s.sessions[id] = adminWebAuthnSession{
		Username:  username,
		Session:   *session,
		ExpiresAt: now + 300,
	}
	s.mu.Unlock()
	return id
}

func (s *adminWebAuthnSessionStore) take(id string) (adminWebAuthnSession, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return adminWebAuthnSession{}, false
	}
	now := time.Now().Unix()
	s.mu.Lock()
	item, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if !ok || item.ExpiresAt <= now {
		return adminWebAuthnSession{}, false
	}
	return item, true
}

func adminPasskeysAllowed(username, group string) bool {
	return strings.TrimSpace(group) != "visitor"
}

func adminPasskeySiteURLReady(db *sql.DB) bool {
	configured := strings.TrimSpace(getOption(db, "siteUrl", ""))
	if configured == "" {
		return false
	}
	normalized := normalizeAdminSiteURL(configured)
	return normalized != "http://localhost:8190"
}

func newAdminWebAuthn(db *sql.DB) (*webauthnlib.WebAuthn, error) {
	siteURL := normalizeAdminSiteURL(getOption(db, "siteUrl", "http://localhost:8190"))
	parsed, err := url.Parse(siteURL)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		siteURL = "http://localhost:8190"
		parsed, _ = url.Parse(siteURL)
	}
	rpID := parsed.Hostname()
	if rpID == "" {
		rpID = "localhost"
	}
	origin := parsed.Scheme + "://" + parsed.Host
	return webauthnlib.New(&webauthnlib.Config{
		RPDisplayName: "Go-TeBlog",
		RPID:          rpID,
		RPOrigins:     []string{origin},
	})
}

func normalizeAdminSiteURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "http://localhost:8190"
	}
	trimmed = strings.TrimRight(trimmed, "/")
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	return "http://" + trimmed
}

func loadAdminWebAuthnUser(db *sql.DB, username string) (adminWebAuthnUser, string, error) {
	var user adminWebAuthnUser
	var group string
	err := db.QueryRow(`SELECT uid, name, COALESCE(screenName, ''), COALESCE("group", 'visitor') FROM typecho_users WHERE name=?`, username).
		Scan(&user.UID, &user.Name, &user.DisplayName, &group)
	if err != nil {
		return user, group, err
	}

	rows, err := db.Query("SELECT credential_json FROM go_passkeys WHERE username=? ORDER BY id ASC", username)
	if err != nil {
		return user, group, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var credential webauthnlib.Credential
		if err := json.Unmarshal([]byte(raw), &credential); err != nil {
			log.Printf("Passkey credential parse failed for user %s: %v", username, err)
			continue
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, group, nil
}

func loadAdminWebAuthnUserByHandle(db *sql.DB, userHandle []byte) (adminWebAuthnUser, string, error) {
	uidStr := strings.TrimSpace(string(userHandle))
	if uidStr == "" {
		return adminWebAuthnUser{}, "", fmt.Errorf("用户标识为空")
	}
	var username string
	err := db.QueryRow("SELECT name FROM typecho_users WHERE uid=?", uidStr).Scan(&username)
	if err != nil {
		return adminWebAuthnUser{}, "", err
	}
	return loadAdminWebAuthnUser(db, username)
}

func listAdminPasskeys(db *sql.DB, username string) []adminPasskey {
	rows, err := db.Query("SELECT id, credential_id, COALESCE(credential_name, ''), created_at, COALESCE(last_used_at, 0) FROM go_passkeys WHERE username=? ORDER BY created_at DESC, id DESC", username)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var passkeys []adminPasskey
	for rows.Next() {
		var item adminPasskey
		if err := rows.Scan(&item.ID, &item.CredentialID, &item.Name, &item.CreatedAt, &item.LastUsedAt); err == nil {
			item.CreatedAtText = time.Unix(item.CreatedAt, 0).Format("2006-01-02")
			if item.LastUsedAt > 0 {
				item.LastUsedAtText = time.Unix(item.LastUsedAt, 0).Format("2006-01-02")
			}
			passkeys = append(passkeys, item)
		}
	}
	return passkeys
}

func saveAdminPasskey(db *sql.DB, username, name string, credential *webauthnlib.Credential) error {
	if credential == nil {
		return fmt.Errorf("通行密钥数据为空")
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	name = strings.TrimSpace(name)
	if name == "" {
		name = "通行密钥"
	}
	now := time.Now().Unix()
	_, err = db.Exec(`INSERT INTO go_passkeys (username, credential_id, credential_name, credential_json, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(credential_id) DO UPDATE SET credential_name=excluded.credential_name, credential_json=excluded.credential_json, last_used_at=excluded.last_used_at`,
		username, credentialID, name, string(raw), now, now)
	return err
}

func updateAdminPasskeyUse(db *sql.DB, username string, credential *webauthnlib.Credential) {
	if credential == nil {
		return
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		log.Printf("Passkey credential marshal failed for user %s: %v", username, err)
		return
	}
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	_, err = db.Exec("UPDATE go_passkeys SET credential_json=?, last_used_at=? WHERE username=? AND credential_id=?",
		string(raw), time.Now().Unix(), username, credentialID)
	if err != nil {
		log.Printf("Passkey credential update failed for user %s: %v", username, err)
	}
}

func createAdminSession(db *sql.DB, c *gin.Context, username string) error {
	timeout := getOptionInt(db, "sessionTimeout", 30) * 60
	db.Exec("DELETE FROM go_sessions WHERE created_at < ?", time.Now().Unix()-int64(timeout))
	db.Exec("DELETE FROM go_sessions WHERE username = ?", username)
	db.Exec("UPDATE typecho_users SET logged = ? WHERE name = ?", time.Now().Unix(), username)

	sessionID := uuid.New().String()
	_, err := db.Exec("INSERT INTO go_sessions (session_id, username, created_at) VALUES (?, ?, ?)",
		sessionID, username, time.Now().Unix())
	if err != nil {
		return err
	}
	c.SetCookie("te_auth", sessionID, timeout, "/", "", false, true)
	return nil
}

func webAuthnOptionsJSON(value interface{}) template.JS {
	raw, err := json.Marshal(value)
	if err != nil {
		return template.JS("null")
	}
	return template.JS(raw)
}

type adminTOTPStatus struct {
	Enabled bool
	Secret  string
	URI     string
}

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func normalizeTOTPCode(code string) string {
	code = strings.ReplaceAll(code, " ", "")
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return ""
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return code
}

func hotpCode(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1000000), nil
}

func verifyTOTPCode(secret, code string, now time.Time) bool {
	code = normalizeTOTPCode(code)
	if code == "" || strings.TrimSpace(secret) == "" {
		return false
	}
	counter := now.Unix() / 30
	for skew := int64(-1); skew <= 1; skew++ {
		expected, err := hotpCode(secret, counter+skew)
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func getTOTPStatus(db *sql.DB, username, issuer string) adminTOTPStatus {
	var status adminTOTPStatus
	var enabled int
	err := db.QueryRow("SELECT COALESCE(secret, ''), COALESCE(enabled, 0) FROM go_totp_settings WHERE username=?", username).
		Scan(&status.Secret, &enabled)
	if err != nil {
		return status
	}
	status.Enabled = enabled == 1
	status.URI = buildTOTPURI(username, status.Secret, issuer)
	return status
}

func ensureTOTPSetup(db *sql.DB, username, issuer string) adminTOTPStatus {
	status := getTOTPStatus(db, username, issuer)
	if status.Secret != "" {
		return status
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		log.Printf("Failed to generate TOTP secret for user %s: %v", username, err)
		return status
	}
	now := time.Now().Unix()
	_, err = db.Exec(`INSERT INTO go_totp_settings (username, secret, enabled, created_at, updated_at)
		VALUES (?, ?, 0, ?, ?)
		ON CONFLICT(username) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at`,
		username, secret, now, now)
	if err != nil {
		log.Printf("Failed to save TOTP secret for user %s: %v", username, err)
		return status
	}
	status.Secret = secret
	status.URI = buildTOTPURI(username, secret, issuer)
	return status
}

func buildTOTPURI(username, secret, issuer string) string {
	if strings.TrimSpace(secret) == "" {
		return ""
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = "localhost"
	}
	label := url.QueryEscape(issuer + ":" + username)
	issuerParam := url.QueryEscape(issuer)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, issuerParam)
}

func getTOTPIssuer(db *sql.DB) string {
	siteURL := normalizeAdminSiteURL(getOption(db, "siteUrl", "http://localhost:8190"))
	parsed, err := url.Parse(siteURL)
	if err != nil {
		return "localhost"
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "localhost"
	}
	return host
}

func buildTOTPQRCodeDataURL(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	png, err := qrcode.Encode(uri, qrcode.Medium, 220)
	if err != nil {
		log.Printf("Failed to generate TOTP QR code: %v", err)
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

func adminTOTPAllowed(username, group string) bool {
	return strings.TrimSpace(group) != "visitor"
}

func getSkinConfig(db *sql.DB) SkinConfig {
	theme := sanitizeThemeName(getOption(db, "theme", "default"), "default")
	return SkinConfig{
		Theme:               theme,
		ThemeBase:           "/blog/usr/themes/" + theme,
		PrimaryColor:        sanitizeSkinColor(getOption(db, "primaryColor", "#3b82f6"), "#3b82f6"),
		PrimaryHover:        sanitizeSkinColor(getOption(db, "primaryHover", "#2563eb"), "#2563eb"),
		SuccessColor:        sanitizeSkinColor(getOption(db, "successColor", "#10b981"), "#10b981"),
		TextPrimary:         sanitizeSkinColor(getOption(db, "textPrimary", "#1f2937"), "#1f2937"),
		TextSecondary:       sanitizeSkinColor(getOption(db, "textSecondary", "#6b7280"), "#6b7280"),
		TextMuted:           sanitizeSkinColor(getOption(db, "textMuted", "#9ca3af"), "#9ca3af"),
		BgPrimary:           sanitizeSkinColor(getOption(db, "bgPrimary", "#f3f4f6"), "#f3f4f6"),
		BgSecondary:         sanitizeSkinColor(getOption(db, "bgSecondary", "#e5e7eb"), "#e5e7eb"),
		BgAccent:            sanitizeSkinColor(getOption(db, "bgAccent", "#d1d5db"), "#d1d5db"),
		BorderLight:         sanitizeSkinColor(getOption(db, "borderLight", "#c5c9d1"), "#c5c9d1"),
		HeaderBg:            sanitizeSkinColor(getOption(db, "headerBg", "rgba(243, 244, 246, 0.8)"), "rgba(243, 244, 246, 0.8)"),
		ThemeBtnHoverBg:     sanitizeSkinColor(getOption(db, "themeBtnHoverBg", "rgba(31, 41, 55, 0.06)"), "rgba(31, 41, 55, 0.06)"),
		ThemeBtnActiveBg:    sanitizeSkinColor(getOption(db, "themeBtnActiveBg", "rgba(59, 130, 246, 0.14)"), "rgba(59, 130, 246, 0.14)"),
		Radius:              sanitizeSkinLength(getOption(db, "radius", "8px"), "8px"),
		LayoutContainerMax:  sanitizeSkinLength(getOption(db, "layoutContainerMax", "1000px"), "1000px"),
		LayoutContainerPad:  sanitizeSkinLength(getOption(db, "layoutContainerPad", "15px"), "15px"),
		LayoutColumnGap:     sanitizeSkinLength(getOption(db, "layoutColumnGap", "10px"), "10px"),
		LayoutPagePadding:   sanitizeSkinLength(getOption(db, "layoutPagePadding", "15px"), "15px"),
		LayoutPostPadding:   sanitizeSkinLength(getOption(db, "layoutPostPadding", "32px"), "32px"),
		LayoutWidgetPadding: sanitizeSkinLength(getOption(db, "layoutWidgetPadding", "16px"), "16px"),
	}
}

func sanitizeThemeName(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || !skinThemeNamePattern.MatchString(value) {
		return fallback
	}
	return value
}

func sanitizeSkinColor(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || !skinColorPattern.MatchString(value) {
		return fallback
	}
	return value
}

func sanitizeSkinLength(value, fallback string) string {
	value = strings.TrimSpace(value)
	match := skinLengthPattern.FindStringSubmatch(value)
	if match == nil {
		return fallback
	}
	if match[1] == "0" || match[2] != "" {
		return strings.ToLower(value)
	}
	return match[1] + "px"
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

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS go_passkeys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		credential_id TEXT NOT NULL UNIQUE,
		credential_name TEXT,
		credential_json TEXT NOT NULL,
		created_at INTEGER,
		last_used_at INTEGER DEFAULT 0
	)`)
	if err != nil {
		log.Fatal("Failed to create passkeys table:", err)
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_go_passkeys_username ON go_passkeys (username)`)
	if err != nil {
		log.Fatal("Failed to create passkeys index:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS go_totp_settings (
		username TEXT PRIMARY KEY,
		secret TEXT NOT NULL,
		enabled INTEGER DEFAULT 0,
		created_at INTEGER,
		updated_at INTEGER
	)`)
	if err != nil {
		log.Fatal("Failed to create TOTP settings table:", err)
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

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS go_cf_shield_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip VARCHAR(64),
		path VARCHAR(255),
		ua VARCHAR(511),
		blocked_ips TEXT,
		created INTEGER
	)`)
	if err != nil {
		log.Fatal("Failed to create Cloudflare shield logs table:", err)
	}
	_, err = db.Exec(`ALTER TABLE go_cf_shield_logs ADD COLUMN blocked_ips TEXT`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		log.Fatal("Failed to update Cloudflare shield logs table:", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_cf_shield_logs_created ON go_cf_shield_logs (created)`)
	if err != nil {
		log.Fatal("Failed to create Cloudflare shield logs index:", err)
	}

	applyConfiguredTimezone(db)
	go startBackupScheduleWorker(db)

	adminPath := getOption(db, "adminPath", "admin")
	if !strings.HasPrefix(adminPath, "/") {
		adminPath = "/" + adminPath
	}
	adminPath = strings.TrimSuffix(adminPath, "/")

	r := gin.Default()
	r.SetTrustedProxies(nil)
	mdRenderer := goldmark.New(
		goldmark.WithExtensions(extension.Linkify),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithUnsafe(),
		),
	)
	passkeySessions := newAdminWebAuthnSessionStore()
	r.SetFuncMap(template.FuncMap{
		"now": func() time.Time { return time.Now() },
		"substring": func(s string, l int) string {
			runes := []rune(s)
			if len(runes) > l {
				return string(runes[:l]) + "..."
			}
			return s
		},
		"gravatarURL": func(mail string) string {
			normalized := strings.ToLower(strings.TrimSpace(mail))
			hash := md5.Sum([]byte(normalized))
			return fmt.Sprintf("https://www.gravatar.com/avatar/%x?s=80&d=identicon", hash)
		},
		"userGravatar": func(name string) string {
			var mail string
			err := db.QueryRow("SELECT COALESCE(mail, '') FROM typecho_users WHERE name = ?", name).Scan(&mail)
			if err != nil || strings.TrimSpace(mail) == "" {
				fallback := strings.ToLower(strings.TrimSpace(name))
				hash := md5.Sum([]byte(fallback))
				return fmt.Sprintf("https://www.gravatar.com/avatar/%x?s=80&d=identicon", hash)
			}
			normalized := strings.ToLower(strings.TrimSpace(mail))
			hash := md5.Sum([]byte(normalized))
			return fmt.Sprintf("https://www.gravatar.com/avatar/%x?s=80&d=identicon", hash)
		},
		"adminPath":      func() string { return adminPath },
		"passkeyOptions": webAuthnOptionsJSON,
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
		db.QueryRow("SELECT COALESCE(\"group\", 'visitor') FROM typecho_users WHERE name = ?", username).Scan(&userGroup)

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
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		wantsJSON := strings.Contains(c.GetHeader("Accept"), "application/json") || c.GetHeader("X-Requested-With") == "XMLHttpRequest"

		var storedHash, userGroup string
		err := db.QueryRow(`SELECT password, COALESCE("group", 'visitor') FROM typecho_users WHERE name=?`, username).Scan(&storedHash, &userGroup)

		if err == nil && checkTypechoHash(password, storedHash) {
			totp := getTOTPStatus(db, username, getTOTPIssuer(db))
			totpCode := c.PostForm("totp_code")
			if adminTOTPAllowed(username, userGroup) && totp.Enabled && !verifyTOTPCode(totp.Secret, totpCode, time.Now()) {
				message := "请输入 Google 验证器中的 6 位验证码。"
				if normalizeTOTPCode(totpCode) != "" {
					message = "验证码错误，请重新输入。"
				}
				if wantsJSON {
					c.JSON(http.StatusUnauthorized, gin.H{
						"success":           false,
						"twoFactorRequired": true,
						"message":           message,
					})
					return
				}
				c.HTML(http.StatusUnauthorized, "admin_login.html", gin.H{
					"AdminPath":         adminPath,
					"Username":          username,
					"InfoMessage":       message,
					"TwoFactorRequired": true,
				})
				return
			}
			if err := createAdminSession(db, c, username); err != nil {
				if wantsJSON {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "创建会话时出现错误，请重新尝试登录。"})
					return
				}
				c.HTML(http.StatusInternalServerError, "admin_error.html", gin.H{
					"AdminPath":    adminPath,
					"ErrorTitle":   "登录失败",
					"ErrorMessage": "创建会话时出现错误，请重新尝试登录。",
				})
				return
			}
			if wantsJSON {
				c.JSON(http.StatusOK, gin.H{"success": true, "redirect": adminPath + "/dashboard"})
			} else {
				c.Redirect(http.StatusFound, adminPath+"/dashboard")
			}
		} else {
			if wantsJSON {
				c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "用户名或密码错误，请重新输入。"})
				return
			}
			c.HTML(http.StatusUnauthorized, "admin_error.html", gin.H{
				"AdminPath":    adminPath,
				"ErrorTitle":   "登录失败",
				"ErrorMessage": "用户名或密码错误，请重新输入。",
			})
		}
	})

	r.POST(adminPath+"/login/passkey/options", func(c *gin.Context) {
		if !adminPasskeySiteURLReady(db) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请先在系统设置中配置正确的站点地址，再使用通行密钥登录。"})
			return
		}
		webauthn, err := newAdminWebAuthn(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥服务初始化失败"})
			return
		}
		options, session, err := webauthn.BeginDiscoverableLogin(webauthnlib.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥验证初始化失败"})
			return
		}
		challengeID := passkeySessions.put("", session)
		if challengeID == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥挑战创建失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "challenge": challengeID, "options": options})
	})

	r.POST(adminPath+"/login/passkey", func(c *gin.Context) {
		challengeID := strings.TrimSpace(c.Query("challenge"))
		challenge, ok := passkeySessions.take(challengeID)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "通行密钥验证已过期，请重新登录。"})
			return
		}

		webauthn, err := newAdminWebAuthn(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥服务初始化失败"})
			return
		}
		discoveredUsername := ""
		handler := func(rawID, userHandle []byte) (webauthnlib.User, error) {
			webAuthnUser, group, err := loadAdminWebAuthnUserByHandle(db, userHandle)
			if err != nil {
				return nil, err
			}
			if !adminPasskeysAllowed(webAuthnUser.Name, group) || len(webAuthnUser.Credentials) == 0 {
				return nil, fmt.Errorf("当前账号不可使用通行密钥")
			}
			discoveredUsername = webAuthnUser.Name
			return webAuthnUser, nil
		}
		credential, err := webauthn.FinishDiscoverableLogin(handler, challenge.Session, c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "通行密钥验证失败。"})
			return
		}
		if discoveredUsername == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "通行密钥账号识别失败。"})
			return
		}
		updateAdminPasskeyUse(db, discoveredUsername, credential)
		if err := createAdminSession(db, c, discoveredUsername); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "创建会话失败，请重新登录。"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "redirect": adminPath + "/dashboard"})
	})

	r.GET(adminPath, func(c *gin.Context) {
		c.Redirect(http.StatusFound, adminPath+"/dashboard")
	})

	admin := r.Group(adminPath, authMiddleware)

	attachmentPathRe := regexp.MustCompile(`"path"\s*:\s*"([^"]+)"`)
	resolveAttachmentPath := func(title, text string) string {
		normalize := func(p string) string {
			p = strings.TrimSpace(strings.ReplaceAll(p, `\/`, `/`))
			if p == "" {
				return ""
			}
			if strings.HasPrefix(p, "/blog/usr/") {
				return p
			}
			if strings.HasPrefix(p, "/usr/") {
				return "/blog" + p
			}
			if strings.HasPrefix(p, "usr/") {
				return "/blog/" + p
			}
			return p
		}

		normalizedTitle := normalize(title)
		if strings.HasPrefix(normalizedTitle, "/blog/usr/") {
			return normalizedTitle
		}
		matched := attachmentPathRe.FindStringSubmatch(text)
		if len(matched) > 1 {
			normalizedPath := normalize(matched[1])
			if normalizedPath != "" {
				return normalizedPath
			}
		}
		return normalizedTitle
	}

	cleanupAttachmentReference := func(attCid string) int {
		var relPathTitle, relPathText string
		var parentCid int
		err := db.QueryRow("SELECT title, text, parent FROM typecho_contents WHERE cid=? AND type='attachment'", attCid).Scan(&relPathTitle, &relPathText, &parentCid)
		relPath := resolveAttachmentPath(relPathTitle, relPathText)
		if err != nil || relPath == "" || parentCid <= 0 {
			return parentCid
		}

		var postText string
		err = db.QueryRow("SELECT text FROM typecho_contents WHERE cid=? AND type='post'", parentCid).Scan(&postText)
		if err != nil || postText == "" {
			return parentCid
		}

		escapedPath := regexp.QuoteMeta(relPath)
		imageRefPattern := regexp.MustCompile(`!\[[^\]]*\]\(` + escapedPath + `(?:\s+"[^"]*")?\)`)
		linkRefPattern := regexp.MustCompile(`\[[^\]]*\]\(` + escapedPath + `(?:\s+"[^"]*")?\)`)
		compactedLineBreaks := regexp.MustCompile(`\n{3,}`)

		newText := imageRefPattern.ReplaceAllString(postText, "")
		newText = linkRefPattern.ReplaceAllString(newText, "")
		newText = compactedLineBreaks.ReplaceAllString(newText, "\n\n")
		if newText != postText {
			_, _ = db.Exec("UPDATE typecho_contents SET text=?, modified=? WHERE cid=?", newText, time.Now().Unix(), parentCid)
		}
		return parentCid
	}

	admin.GET("/dashboard", func(c *gin.Context) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")
		group, _ := c.Get("userGroup")
		frontendServiceName := strings.TrimSpace(getOption(db, "frontendServiceName", "blog"))
		if frontendServiceName == "" {
			frontendServiceName = "blog"
		}
		adminServiceName := strings.TrimSpace(getOption(db, "adminServiceName", "blogadmin"))
		if adminServiceName == "" {
			adminServiceName = "blogadmin"
		}

		// 基础统计
		var postCount, commentCount, attachmentCount int
		var recentPostCount, recentCommentCount, recentAttachmentCount int
		now := time.Now()

		// 统计近 7 天滚动窗口（含当前时刻往前 7 天）
		recentStart := now.AddDate(0, 0, -7).Unix()

		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='post'").Scan(&postCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments").Scan(&commentCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='attachment'").Scan(&attachmentCount)

		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='post' AND created >= ?", recentStart).Scan(&recentPostCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_comments WHERE created >= ?", recentStart).Scan(&recentCommentCount)
		db.QueryRow("SELECT COUNT(*) FROM typecho_contents WHERE type='attachment' AND created >= ?", recentStart).Scan(&recentAttachmentCount)

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

		// 获取日志保留天数设置，用于前端标签展示与折线图范围
		retentionStr := getOption(db, "logRetentionDays", "30")
		retentionDays, err := strconv.Atoi(strings.TrimSpace(retentionStr))
		if err != nil || retentionDays < 0 {
			retentionDays = 30
		}
		retentionLabel := retentionStr + "天内"
		if retentionDays == 0 {
			retentionLabel = "历史累计"
		}

		trendDays := retentionDays
		if trendDays == 0 {
			trendDays = 30
		}

		// 访客趋势（按天去重 IP，按当前配置时区分日）
		visitorTrendStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -(trendDays - 1))
		visitorTrendLabels := make([]string, 0, trendDays)
		humanVisitorTrend := make([]int, 0, trendDays)
		botVisitorTrend := make([]int, 0, trendDays)
		humanPVTrend := make([]int, 0, trendDays)
		botPVTrend := make([]int, 0, trendDays)

		for i := 0; i < trendDays; i++ {
			day := visitorTrendStart.AddDate(0, 0, i)
			visitorTrendLabels = append(visitorTrendLabels, day.Format("01-02"))
			dayStart := day.Unix()
			dayEnd := day.AddDate(0, 0, 1).Unix()
			var humanVisitors, botVisitors, humanPV, botPV int
			db.QueryRow(`
				SELECT
					COUNT(DISTINCT CASE WHEN is_bot = 0 THEN ip END),
					COUNT(DISTINCT CASE WHEN is_bot = 1 THEN ip END),
					COALESCE(SUM(CASE WHEN is_bot = 0 THEN 1 ELSE 0 END), 0),
					COALESCE(SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END), 0)
				FROM go_stats_logs
				WHERE created >= ? AND created < ?
			`, dayStart, dayEnd).Scan(&humanVisitors, &botVisitors, &humanPV, &botPV)
			humanVisitorTrend = append(humanVisitorTrend, humanVisitors)
			botVisitorTrend = append(botVisitorTrend, botVisitors)
			humanPVTrend = append(humanPVTrend, humanPV)
			botPVTrend = append(botPVTrend, botPV)
		}

		visitorTrendLabelsJSON, err := json.Marshal(visitorTrendLabels)
		if err != nil {
			visitorTrendLabelsJSON = []byte("[]")
		}
		humanVisitorTrendJSON, err := json.Marshal(humanVisitorTrend)
		if err != nil {
			humanVisitorTrendJSON = []byte("[]")
		}
		botVisitorTrendJSON, err := json.Marshal(botVisitorTrend)
		if err != nil {
			botVisitorTrendJSON = []byte("[]")
		}
		humanPVTrendJSON, err := json.Marshal(humanPVTrend)
		if err != nil {
			humanPVTrendJSON = []byte("[]")
		}
		botPVTrendJSON, err := json.Marshal(botPVTrend)
		if err != nil {
			botPVTrendJSON = []byte("[]")
		}

		type cfShieldLogItem struct {
			ID         int64
			IP         string
			Path       string
			Created    int64
			CreatedAt  string
			UA         string
			BlockedIPs string
		}

		var cfShieldLogCount int
		var latestCfShieldIP string
		var latestCfShieldCreated int64
		var cfShieldLogs []cfShieldLogItem

		db.QueryRow("SELECT COUNT(*) FROM go_cf_shield_logs").Scan(&cfShieldLogCount)
		db.QueryRow("SELECT COALESCE(ip, ''), COALESCE(created, 0) FROM go_cf_shield_logs ORDER BY created DESC, id DESC LIMIT 1").Scan(&latestCfShieldIP, &latestCfShieldCreated)

		rows, err := db.Query("SELECT id, COALESCE(ip, ''), COALESCE(path, '/'), COALESCE(ua, ''), COALESCE(blocked_ips, ''), created FROM go_cf_shield_logs ORDER BY created DESC, id DESC LIMIT 10")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var item cfShieldLogItem
				var created int64
				if err := rows.Scan(&item.ID, &item.IP, &item.Path, &item.UA, &item.BlockedIPs, &created); err == nil {
					item.Created = created
					item.CreatedAt = time.Unix(created, 0).Format("2006-01-02 15:04:05")
					cfShieldLogs = append(cfShieldLogs, item)
				}
			}
		}

		// 数据库大小
		dbFile, _ := os.Stat("blog.sqlite")
		dbSize := "0 MB"
		if dbFile != nil {
			dbSize = fmt.Sprintf("%.2f MB", float64(dbFile.Size())/(1024*1024))
		}

		// 内存单位转换（自动选择 MB/GB）
		formatMem := func(mb float64) string {
			if mb >= 1024 {
				return fmt.Sprintf("%.2f GB", mb/1024)
			}
			return fmt.Sprintf("%.2f MB", mb)
		}

		// 系统信息
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memUsed := formatMem(float64(m.Alloc) / (1024 * 1024))

		var totalMem int
		var totalMemMB float64
		var availableMemMB float64
		systemUptime := "获取失败"
		var si syscall.Sysinfo_t
		if err := syscall.Sysinfo(&si); err == nil {
			// 将字节转换为 GB，并取整（向上取整以补偿内核占用空间）
			ramBytes := float64(si.Totalram) * float64(si.Unit)
			totalMem = int((ramBytes + (512 * 1024 * 1024)) / (1024 * 1024 * 1024))
			totalMemMB = ramBytes / (1024 * 1024)
			// 默认使用 syscall 的 Freeram（跨平台兼容）
			availableMemMB = float64(si.Freeram) * float64(si.Unit) / (1024 * 1024)

			uptimeSeconds := int64(si.Uptime)
			days := uptimeSeconds / 86400
			hours := (uptimeSeconds % 86400) / 3600
			minutes := (uptimeSeconds % 3600) / 60
			seconds := uptimeSeconds % 60
			if days > 0 {
				systemUptime = fmt.Sprintf("%d 天 %d 小时 %d 分钟 %d 秒", days, hours, minutes, seconds)
			} else if hours > 0 {
				systemUptime = fmt.Sprintf("%d 小时 %d 分钟 %d 秒", hours, minutes, seconds)
			} else if minutes > 0 {
				systemUptime = fmt.Sprintf("%d 分钟 %d 秒", minutes, seconds)
			} else {
				systemUptime = fmt.Sprintf("%d 秒", seconds)
			}
		}

		// Linux 上尝试获取 MemAvailable（更准确的可用内存，包含 buffer/cache）
		if runtime.GOOS == "linux" {
			if data, err := os.ReadFile("/proc/meminfo"); err == nil {
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "MemAvailable:") {
						parts := strings.Fields(line)
						if len(parts) >= 2 {
							if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
								availableMemMB = float64(kb) / 1024
							}
							break
						}
					}
				}
			}
		}

		systemMem := "获取失败"
		memoryPercent := 0
		if totalMemMB > 0 {
			usedMemMB := totalMemMB - availableMemMB
			if usedMemMB < 0 {
				usedMemMB = 0
			}
			memoryPercent = int(usedMemMB/totalMemMB*100 + 0.5)
			systemMem = fmt.Sprintf("%s 已用 / %s 总计", formatMem(usedMemMB), formatMem(totalMemMB))
		}

		// 剩余磁盘空间 (/)
		var diskFree string
		diskPercent := 0
		var fs syscall.Statfs_t
		if err := syscall.Statfs("/", &fs); err == nil {
			free := float64(fs.Bavail*uint64(fs.Bsize)) / (1024 * 1024 * 1024)
			total := float64(fs.Blocks*uint64(fs.Bsize)) / (1024 * 1024 * 1024)
			used := total - free
			if used < 0 {
				used = 0
			}
			if total > 0 {
				diskPercent = int(used/total*100 + 0.5)
			}
			diskFree = fmt.Sprintf("%.1f GB 已用 / %.1f GB 总计", used, total)
		} else {
			diskFree = "获取失败"
		}

		storageInfo := getCachedDashboardStorageInfo(db)

		// 系统负载
		var sysLoad string
		loadPercent := 0
		if loadData, err := os.ReadFile("/proc/loadavg"); err == nil {
			parts := strings.Fields(string(loadData))
			if len(parts) >= 3 {
				sysLoad = fmt.Sprintf("%s / %s / %s (1/5/15 min)", parts[0], parts[1], parts[2])
				if oneMinuteLoad, err := strconv.ParseFloat(parts[0], 64); err == nil && runtime.NumCPU() > 0 {
					loadPercent = int(oneMinuteLoad/float64(runtime.NumCPU())*100 + 0.5)
				}
			} else {
				sysLoad = "解析失败"
			}
		} else {
			sysLoad = "不支持 (Linux)"
		}

		cfShieldActive := getOption(db, "cfShieldActive", "0") == "1"
		cfShieldStatus := "未激活"
		cfShieldUntil := "未开启"
		cfShieldLatest := "暂无拦截日志"
		if cfShieldActive {
			cfShieldStatus = "已开启"
			untilUnix, err := strconv.ParseInt(strings.TrimSpace(getOption(db, "cfShieldUntil", "0")), 10, 64)
			if err == nil && untilUnix > 0 {
				cfShieldUntil = time.Unix(untilUnix, 0).Format("2006-01-02 15:04:05")
			} else {
				cfShieldUntil = "已开启（未获取到关闭时间）"
			}
		}
		if latestCfShieldIP != "" && latestCfShieldCreated > 0 {
			cfShieldLatest = fmt.Sprintf("最近触发来源: %s / %s", latestCfShieldIP, time.Unix(latestCfShieldCreated, 0).Format("2006-01-02 15:04:05"))
		}

		c.HTML(http.StatusOK, "admin_dashboard.html", gin.H{
			"Username":              username,
			"UserGroup":             group,
			"Tab":                   "dashboard",
			"AdminPath":             adminPath,
			"FrontendServiceName":   frontendServiceName,
			"AdminServiceName":      adminServiceName,
			"PostCount":             postCount,
			"CommentCount":          commentCount,
			"RecentPostCount":       recentPostCount,
			"RecentCommentCount":    recentCommentCount,
			"AttachmentCount":       attachmentCount,
			"RecentAttachmentCount": recentAttachmentCount,
			"TodayPV":               todayPV,
			"TodayIP":               todayHumanIP,
			"TodayBotIP":            todayBotIP,
			"TotalPV":               totalHumanPV,
			"TotalIP":               totalHumanIP,
			"TodayBotPV":            todayBotPV,
			"TotalBotPV":            totalBotPV,
			"TotalBotIP":            totalBotIP,
			"VisitorTrendLabels":    template.JS(visitorTrendLabelsJSON),
			"HumanVisitorTrend":     template.JS(humanVisitorTrendJSON),
			"BotVisitorTrend":       template.JS(botVisitorTrendJSON),
			"HumanPVTrend":          template.JS(humanPVTrendJSON),
			"BotPVTrend":            template.JS(botPVTrendJSON),
			"VisitorTrendDays":      trendDays,
			"RetentionLabel":        retentionLabel,
			"DbSize":                dbSize,
			"MemUsed":               memUsed,
			"SystemMem":             systemMem,
			"MemoryPercent":         memoryPercent,
			"SystemUptime":          systemUptime,
			"GoVersion":             runtime.Version(),
			"OS":                    runtime.GOOS,
			"Arch":                  runtime.GOARCH,
			"CPUs":                  runtime.NumCPU(),
			"TotalMem":              totalMem,
			"UploadSize":            storageInfo.UploadSize,
			"BackupSize":            storageInfo.BackupSize,
			"LastBackupTime":        storageInfo.LastBackupTime,
			"DiskFree":              diskFree,
			"DiskPercent":           diskPercent,
			"SysLoad":               sysLoad,
			"LoadPercent":           loadPercent,
			"CfShieldActive":        cfShieldActive,
			"CfShieldStatus":        cfShieldStatus,
			"CfShieldUntil":         cfShieldUntil,
			"CfShieldLogCount":      cfShieldLogCount,
			"CfShieldLatest":        cfShieldLatest,
			"CfShieldLogs":          cfShieldLogs,
			"CfMinuteLimit":         getOption(db, "cfRequestLimitPerMinute", "1000"),
			"CfAutoDisableMinutes":  getOption(db, "cfShieldAutoDisableMinutes", "30"),
		})
	})

	admin.GET("/dashboard/system-resources", func(c *gin.Context) {
		formatMem := func(mb float64) string {
			if mb >= 1024 {
				return fmt.Sprintf("%.2f GB", mb/1024)
			}
			return fmt.Sprintf("%.2f MB", mb)
		}

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		goMemory := formatMem(float64(memStats.Alloc) / (1024 * 1024))

		memorySummary := "获取失败"
		memoryPercent := 0
		uptime := "获取失败"
		var totalMemMB float64
		var availableMemMB float64
		var si syscall.Sysinfo_t
		if err := syscall.Sysinfo(&si); err == nil {
			totalMemMB = float64(si.Totalram) * float64(si.Unit) / (1024 * 1024)
			availableMemMB = float64(si.Freeram) * float64(si.Unit) / (1024 * 1024)

			uptimeSeconds := int64(si.Uptime)
			days := uptimeSeconds / 86400
			hours := (uptimeSeconds % 86400) / 3600
			minutes := (uptimeSeconds % 3600) / 60
			seconds := uptimeSeconds % 60
			if days > 0 {
				uptime = fmt.Sprintf("%d 天 %d 小时 %d 分钟 %d 秒", days, hours, minutes, seconds)
			} else if hours > 0 {
				uptime = fmt.Sprintf("%d 小时 %d 分钟 %d 秒", hours, minutes, seconds)
			} else if minutes > 0 {
				uptime = fmt.Sprintf("%d 分钟 %d 秒", minutes, seconds)
			} else {
				uptime = fmt.Sprintf("%d 秒", seconds)
			}
		}

		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(line, "MemAvailable:") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						availableMemMB = float64(kb) / 1024
					}
				}
				break
			}
		}

		if totalMemMB > 0 {
			usedMemMB := totalMemMB - availableMemMB
			if usedMemMB < 0 {
				usedMemMB = 0
			}
			memoryPercent = int(usedMemMB/totalMemMB*100 + 0.5)
			memorySummary = fmt.Sprintf("%s 已用 / %s 总计", formatMem(usedMemMB), formatMem(totalMemMB))
		}

		loadSummary := "不支持 (Linux)"
		loadPercent := 0
		if loadData, err := os.ReadFile("/proc/loadavg"); err == nil {
			parts := strings.Fields(string(loadData))
			if len(parts) >= 3 {
				loadSummary = fmt.Sprintf("%s / %s / %s (1/5/15 min)", parts[0], parts[1], parts[2])
				if oneMinuteLoad, err := strconv.ParseFloat(parts[0], 64); err == nil && runtime.NumCPU() > 0 {
					loadPercent = int(oneMinuteLoad/float64(runtime.NumCPU())*100 + 0.5)
				}
			}
		}

		diskSummary := "获取失败"
		diskPercent := 0
		var fs syscall.Statfs_t
		if err := syscall.Statfs("/", &fs); err == nil {
			free := float64(fs.Bavail*uint64(fs.Bsize)) / (1024 * 1024 * 1024)
			total := float64(fs.Blocks*uint64(fs.Bsize)) / (1024 * 1024 * 1024)
			used := total - free
			if used < 0 {
				used = 0
			}
			if total > 0 {
				diskPercent = int(used/total*100 + 0.5)
			}
			diskSummary = fmt.Sprintf("%.1f GB 已用 / %.1f GB 总计", used, total)
		}

		dbSize := "0 MB"
		if dbFile, err := os.Stat("blog.sqlite"); err == nil {
			dbSize = fmt.Sprintf("%.2f MB", float64(dbFile.Size())/(1024*1024))
		}

		storageInfo := getCachedDashboardStorageInfo(db)

		cfShieldActive := getOption(db, "cfShieldActive", "0") == "1"
		cfShieldStatus := "未激活"
		cfShieldUntil := ""
		if cfShieldActive {
			cfShieldStatus = "已开启"
			untilUnix, err := strconv.ParseInt(strings.TrimSpace(getOption(db, "cfShieldUntil", "0")), 10, 64)
			if err == nil && untilUnix > 0 {
				cfShieldUntil = "(自动关闭: " + time.Unix(untilUnix, 0).Format("2006-01-02 15:04:05") + ")"
			} else {
				cfShieldUntil = "(已开启，未获取到关闭时间)"
			}
		}

		cfShieldLogCount := 0
		latestCfShieldIP := ""
		latestCfShieldCreated := int64(0)
		db.QueryRow("SELECT COUNT(*) FROM go_cf_shield_logs").Scan(&cfShieldLogCount)
		db.QueryRow("SELECT COALESCE(ip, ''), COALESCE(created, 0) FROM go_cf_shield_logs ORDER BY created DESC, id DESC LIMIT 1").Scan(&latestCfShieldIP, &latestCfShieldCreated)
		cfShieldLatest := "暂无拦截日志"
		if latestCfShieldIP != "" && latestCfShieldCreated > 0 {
			cfShieldLatest = fmt.Sprintf("最近触发来源: %s / %s", latestCfShieldIP, time.Unix(latestCfShieldCreated, 0).Format("2006-01-02 15:04:05"))
		}

		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{
			"success":          true,
			"memorySummary":    memorySummary,
			"memoryPercent":    memoryPercent,
			"goMemory":         goMemory,
			"loadSummary":      loadSummary,
			"loadPercent":      loadPercent,
			"uptime":           uptime,
			"diskSummary":      diskSummary,
			"diskPercent":      diskPercent,
			"dbSize":           dbSize,
			"uploadSize":       storageInfo.UploadSize,
			"backupSize":       storageInfo.BackupSize,
			"lastBackupTime":   storageInfo.LastBackupTime,
			"cfShieldStatus":   cfShieldStatus,
			"cfShieldUntil":    cfShieldUntil,
			"cfShieldLatest":   cfShieldLatest,
			"cfShieldLogCount": cfShieldLogCount,
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

	renderProfilePage := func(c *gin.Context, data gin.H) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")
		group, _ := c.Get("userGroup")
		userGroup, _ := group.(string)
		usernameStr := fmt.Sprint(username)
		totpAllowed := adminTOTPAllowed(usernameStr, userGroup)
		totpStatus := adminTOTPStatus{}
		if totpAllowed {
			totpStatus = ensureTOTPSetup(db, usernameStr, getTOTPIssuer(db))
		}
		data["Username"] = username
		data["UserGroup"] = userGroup
		data["Tab"] = "profile"
		data["AdminPath"] = adminPath
		data["Passkeys"] = listAdminPasskeys(db, usernameStr)
		data["PasskeyAllowed"] = adminPasskeysAllowed(usernameStr, userGroup)
		data["PasskeySiteReady"] = adminPasskeySiteURLReady(db)
		data["TwoFactorAllowed"] = totpAllowed
		data["TwoFactorEnabled"] = totpStatus.Enabled
		data["TwoFactorSecret"] = totpStatus.Secret
		data["TwoFactorURI"] = totpStatus.URI
		data["TwoFactorQRCode"] = template.URL(buildTOTPQRCodeDataURL(totpStatus.URI))
		c.HTML(http.StatusOK, "admin_profile.html", data)
	}

	admin.GET("/profile", func(c *gin.Context) {
		renderProfilePage(c, gin.H{})
	})

	admin.POST("/profile/passkey/register/options", writeProtectMiddleware, func(c *gin.Context) {
		username := fmt.Sprint(c.MustGet("username"))
		group, _ := c.Get("userGroup")
		userGroup, _ := group.(string)
		if !adminPasskeysAllowed(username, userGroup) {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "访客用户不能使用通行密钥。"})
			return
		}
		if !adminPasskeySiteURLReady(db) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请先在系统设置中配置正确的站点地址，再绑定通行密钥。"})
			return
		}
		webAuthnUser, _, err := loadAdminWebAuthnUser(db, username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "读取用户信息失败。"})
			return
		}
		webauthn, err := newAdminWebAuthn(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥服务初始化失败。"})
			return
		}
		authSelect := protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		}
		options, session, err := webauthn.BeginRegistration(
			webAuthnUser,
			webauthnlib.WithAuthenticatorSelection(authSelect),
			webauthnlib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥绑定初始化失败。"})
			return
		}
		challengeID := passkeySessions.put(username, session)
		if challengeID == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥挑战创建失败。"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "challenge": challengeID, "options": options})
	})

	admin.POST("/profile/passkey/register/finish", writeProtectMiddleware, func(c *gin.Context) {
		username := fmt.Sprint(c.MustGet("username"))
		group, _ := c.Get("userGroup")
		userGroup, _ := group.(string)
		if !adminPasskeysAllowed(username, userGroup) {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "访客用户不能使用通行密钥。"})
			return
		}
		if !adminPasskeySiteURLReady(db) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请先在系统设置中配置正确的站点地址，再绑定通行密钥。"})
			return
		}
		challengeID := strings.TrimSpace(c.Query("challenge"))
		challenge, ok := passkeySessions.take(challengeID)
		if !ok || challenge.Username != username {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "通行密钥绑定已过期，请重试。"})
			return
		}
		webAuthnUser, _, err := loadAdminWebAuthnUser(db, username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "读取用户信息失败。"})
			return
		}
		webauthn, err := newAdminWebAuthn(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "通行密钥服务初始化失败。"})
			return
		}
		credential, err := webauthn.FinishRegistration(webAuthnUser, challenge.Session, c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "通行密钥绑定失败。"})
			return
		}
		name := strings.TrimSpace(c.Query("name"))
		if err := saveAdminPasskey(db, username, name, credential); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "保存通行密钥失败。"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "通行密钥绑定成功。"})
	})

	admin.POST("/profile/passkey/delete/:id", writeProtectMiddleware, func(c *gin.Context) {
		username := fmt.Sprint(c.MustGet("username"))
		group, _ := c.Get("userGroup")
		userGroup, _ := group.(string)
		if !adminPasskeysAllowed(username, userGroup) {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "访客用户不能使用通行密钥。"})
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "通行密钥编号无效。"})
			return
		}
		result, err := db.Exec("DELETE FROM go_passkeys WHERE id=? AND username=?", id, username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "删除通行密钥失败。"})
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "通行密钥不存在。"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "通行密钥已删除。"})
	})

	admin.POST("/profile/2fa/enable", writeProtectMiddleware, func(c *gin.Context) {
		username := fmt.Sprint(c.MustGet("username"))
		group, _ := c.Get("userGroup")
		userGroup, _ := group.(string)
		if !adminTOTPAllowed(username, userGroup) {
			renderProfilePage(c, gin.H{"ErrorMessage": "访客用户不能启用 2FA。"})
			return
		}
		status := ensureTOTPSetup(db, username, getTOTPIssuer(db))
		if status.Secret == "" || !verifyTOTPCode(status.Secret, c.PostForm("totp_code"), time.Now()) {
			renderProfilePage(c, gin.H{"ErrorMessage": "Google 验证码错误，请重新输入。"})
			return
		}
		_, err := db.Exec("UPDATE go_totp_settings SET enabled=1, updated_at=? WHERE username=?", time.Now().Unix(), username)
		if err != nil {
			renderProfilePage(c, gin.H{"ErrorMessage": "启用 2FA 失败，请稍后重试。"})
			return
		}
		renderProfilePage(c, gin.H{"SuccessMessage": "Google 验证器 2FA 已启用"})
	})

	admin.POST("/profile/2fa/disable", writeProtectMiddleware, func(c *gin.Context) {
		username := fmt.Sprint(c.MustGet("username"))
		group, _ := c.Get("userGroup")
		userGroup, _ := group.(string)
		if !adminTOTPAllowed(username, userGroup) {
			renderProfilePage(c, gin.H{"ErrorMessage": "访客用户不能设置 2FA。"})
			return
		}
		status := getTOTPStatus(db, username, getTOTPIssuer(db))
		if !status.Enabled {
			renderProfilePage(c, gin.H{"SuccessMessage": "Google 验证器 2FA 已关闭"})
			return
		}
		if !verifyTOTPCode(status.Secret, c.PostForm("totp_code"), time.Now()) {
			renderProfilePage(c, gin.H{"ErrorMessage": "Google 验证码错误，请重新输入。"})
			return
		}
		secret, err := generateTOTPSecret()
		if err != nil {
			renderProfilePage(c, gin.H{"ErrorMessage": "关闭 2FA 失败，请稍后重试。"})
			return
		}
		_, err = db.Exec("UPDATE go_totp_settings SET secret=?, enabled=0, updated_at=? WHERE username=?", secret, time.Now().Unix(), username)
		if err != nil {
			renderProfilePage(c, gin.H{"ErrorMessage": "关闭 2FA 失败，请稍后重试。"})
			return
		}
		renderProfilePage(c, gin.H{"SuccessMessage": "Google 验证器 2FA 已关闭"})
	})

	admin.POST("/profile", writeProtectMiddleware, func(c *gin.Context) {
		renderProfile := func(data gin.H) {
			renderProfilePage(c, data)
		}
		username, _ := c.Get("username")
		oldPassword := c.PostForm("old_password")
		newPassword := c.PostForm("new_password")
		confirmPassword := c.PostForm("confirm_password")

		if newPassword != confirmPassword {
			renderProfile(gin.H{
				"ErrorMessage": "两次输入的新密码不一致",
			})
			return
		}

		var storedHash string
		err := db.QueryRow("SELECT password FROM typecho_users WHERE name=?", username).Scan(&storedHash)
		if err != nil || !checkTypechoHash(oldPassword, storedHash) {
			renderProfile(gin.H{
				"ErrorMessage": "旧密码错误",
			})
			return
		}

		newHash := hashTypecho(newPassword)
		_, err = db.Exec("UPDATE typecho_users SET password=? WHERE name=?", newHash, username)
		if err != nil {
			renderProfile(gin.H{
				"ErrorMessage": "数据库更新失败",
			})
			return
		}

		renderProfile(gin.H{
			"SuccessMessage": "密码修改成功",
		})
	})

	renderSettingsPage := func(c *gin.Context, activeSection, successMessage string) {
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
		cfApiToken := getOption(db, "cfApiToken", "")
		cfAuthEmail := getOption(db, "cfAuthEmail", "")
		cfZoneID := getOption(db, "cfZoneID", "")
		backupStorageCfg := getBackupStorageConfig(db)
		backupDraftCfg := getBackupStorageDraftConfig(db)
		backupStorageType := "local"
		if backupStorageCfg.HasAnyValue() {
			backupStorageType = "s3"
		}
		backupS3AccessKey := backupDraftCfg.AccessKey
		backupS3SecretKey := backupDraftCfg.SecretKey
		if group == "visitor" && cfApiToken != "" {
			cfApiToken = "********************************"
		}
		if group == "visitor" && cfAuthEmail != "" {
			cfAuthEmail = "********************************"
		}
		if group == "visitor" && cfZoneID != "" {
			cfZoneID = "********************************"
		}
		if group == "visitor" && backupS3AccessKey != "" {
			backupS3AccessKey = "********************************"
		}
		if group == "visitor" && backupS3SecretKey != "" {
			backupS3SecretKey = "********************************"
		}
		cfEnvConnected := isCloudflareRequest(c)
		cfEnvStatus := "当前未接入 Cloudflare"
		if cfEnvConnected {
			cfEnvStatus = "当前已接入 Cloudflare"
		}

		c.HTML(http.StatusOK, "admin_settings.html", gin.H{
			"Username":                   username,
			"UserGroup":                  group,
			"Tab":                        "settings",
			"ActiveSection":              activeSection,
			"AdminPath":                  adminPath,
			"Skin":                       getSkinConfig(db),
			"SiteTitle":                  getOption(db, "title", "我的博客"),
			"SiteDescription":            getOption(db, "description", "基于 Go 语言的极速博客系统"),
			"SiteUrl":                    getOption(db, "siteUrl", "http://localhost:8190"),
			"Timezone":                   normalizeTimezoneOption(getOption(db, "timezone", "Asia/Shanghai")),
			"ConfigAdminPath":            getOption(db, "adminPath", "admin"),
			"FrontendServiceName":        getOption(db, "frontendServiceName", "blog"),
			"AdminServiceName":           getOption(db, "adminServiceName", "blogadmin"),
			"AiThreshold":                getOption(db, "aiThreshold", "5"),
			"SessionTimeout":             getOption(db, "sessionTimeout", "30"),
			"SiteKeywords":               getOption(db, "keywords", ""),
			"FooterCode":                 getOption(db, "footerCode", ""),
			"PageSize":                   getOption(db, "pageSize", "10"),
			"RecentPostsSize":            getOption(db, "recentPostsSize", "15"),
			"RecentCommentsSize":         getOption(db, "recentCommentsSize", "10"),
			"ShowDateArchives":           getOption(db, "showDateArchives", "1"),
			"DateArchivesSize":           getOption(db, "dateArchivesSize", "12"),
			"GrokApiKey":                 apiKey,
			"AiApiUrl":                   getOption(db, "aiApiUrl", "https://api.groq.com/openai/v1/chat/completions"),
			"AiModel":                    getOption(db, "aiModel", "llama-3.3-70b-versatile"),
			"AiTimeoutSeconds":           getOption(db, "aiTimeoutSeconds", "10"),
			"AiProofreadMaxChars":        getOption(db, "aiProofreadMaxChars", "0"),
			"AiProofreadMaxTokens":       getOption(db, "aiProofreadMaxTokens", "16384"),
			"AiProofreadPrompt":          getOption(db, "aiProofreadPrompt", defaultAIProofreadPrompt()),
			"AiCommentPrompt":            getOption(db, "aiCommentPrompt", defaultAICommentModerationPrompt()),
			"CommentAiDetection":         getOption(db, "commentAiDetection", "1"),
			"DefaultCategory":            getOption(db, "defaultCategory", "1"),
			"CommentAudit":               getOption(db, "commentAudit", "0"),
			"CommentFailClosed":          getOption(db, "commentFailClosed", "0"),
			"StatsBufferSize":            getOption(db, "statsBufferSize", "100"),
			"LogRetentionDays":           getOption(db, "logRetentionDays", "30"),
			"CommentLimitIP":             getOption(db, "commentLimitIP", "1"),
			"CommentLimitGlobal":         getOption(db, "commentLimitGlobal", "2"),
			"CommentsEnabled":            getOption(db, "commentsEnabled", "1"),
			"CfRequestLimitPerMinute":    getOption(db, "cfRequestLimitPerMinute", "1000"),
			"CfApiToken":                 cfApiToken,
			"CfAuthEmail":                cfAuthEmail,
			"CfZoneID":                   cfZoneID,
			"CfRestoreSecurityLevel":     getOption(db, "cfRestoreSecurityLevel", "medium"),
			"CfShieldAutoDisableMinutes": getOption(db, "cfShieldAutoDisableMinutes", "30"),
			"CfShieldAutoBlockIP":        getOption(db, "cfShieldAutoBlockIP", "0"),
			"BackupStorageType":          backupStorageType,
			"BackupS3Endpoint":           backupDraftCfg.Endpoint,
			"BackupS3Region":             backupDraftCfg.Region,
			"BackupS3Bucket":             backupDraftCfg.Bucket,
			"BackupS3AccessKey":          backupS3AccessKey,
			"BackupS3SecretKey":          backupS3SecretKey,
			"BackupS3Prefix":             backupDraftCfg.Prefix,
			"BackupS3ForcePathStyle":     map[bool]string{true: "1", false: "0"}[backupDraftCfg.ForcePathStyle],
			"CfEnvConnected":             cfEnvConnected,
			"CfEnvStatus":                cfEnvStatus,
			"AllCategories":              categories,
			"SuccessMessage":             successMessage,
		})
	}

	admin.GET("/settings", func(c *gin.Context) {
		renderSettingsPage(c, "basic", "")
	})

	admin.GET("/settings/skin", func(c *gin.Context) {
		renderSettingsPage(c, "skin", "")
	})

	admin.POST("/settings/skin", writeProtectMiddleware, func(c *gin.Context) {
		activeSection := "skin"
		theme := strings.TrimSpace(c.PostForm("theme"))
		primaryColor := strings.TrimSpace(c.PostForm("primaryColor"))
		primaryHover := strings.TrimSpace(c.PostForm("primaryHover"))
		successColor := strings.TrimSpace(c.PostForm("successColor"))
		textPrimary := strings.TrimSpace(c.PostForm("textPrimary"))
		textSecondary := strings.TrimSpace(c.PostForm("textSecondary"))
		textMuted := strings.TrimSpace(c.PostForm("textMuted"))
		bgPrimary := strings.TrimSpace(c.PostForm("bgPrimary"))
		bgSecondary := strings.TrimSpace(c.PostForm("bgSecondary"))
		bgAccent := strings.TrimSpace(c.PostForm("bgAccent"))
		borderLight := strings.TrimSpace(c.PostForm("borderLight"))
		headerBg := strings.TrimSpace(c.PostForm("headerBg"))
		themeBtnHoverBg := strings.TrimSpace(c.PostForm("themeBtnHoverBg"))
		themeBtnActiveBg := strings.TrimSpace(c.PostForm("themeBtnActiveBg"))
		radius := strings.TrimSpace(c.PostForm("radius"))
		layoutContainerMax := strings.TrimSpace(c.PostForm("layoutContainerMax"))
		layoutContainerPad := strings.TrimSpace(c.PostForm("layoutContainerPad"))
		layoutColumnGap := strings.TrimSpace(c.PostForm("layoutColumnGap"))
		layoutPagePadding := strings.TrimSpace(c.PostForm("layoutPagePadding"))
		layoutPostPadding := strings.TrimSpace(c.PostForm("layoutPostPadding"))
		layoutWidgetPadding := strings.TrimSpace(c.PostForm("layoutWidgetPadding"))
		if theme == "" {
			theme = "default"
		}
		if radius == "" {
			radius = "8px"
		}
		if layoutContainerMax == "" {
			layoutContainerMax = "1000px"
		}
		if layoutContainerPad == "" {
			layoutContainerPad = "15px"
		}
		if layoutColumnGap == "" {
			layoutColumnGap = "10px"
		}
		if layoutPagePadding == "" {
			layoutPagePadding = "15px"
		}
		if layoutPostPadding == "" {
			layoutPostPadding = "32px"
		}
		if layoutWidgetPadding == "" {
			layoutWidgetPadding = "16px"
		}

		setOption(db, "theme", theme)
		setOption(db, "primaryColor", primaryColor)
		setOption(db, "primaryHover", primaryHover)
		setOption(db, "successColor", successColor)
		setOption(db, "textPrimary", textPrimary)
		setOption(db, "textSecondary", textSecondary)
		setOption(db, "textMuted", textMuted)
		setOption(db, "bgPrimary", bgPrimary)
		setOption(db, "bgSecondary", bgSecondary)
		setOption(db, "bgAccent", bgAccent)
		setOption(db, "borderLight", borderLight)
		setOption(db, "headerBg", headerBg)
		setOption(db, "themeBtnHoverBg", themeBtnHoverBg)
		setOption(db, "themeBtnActiveBg", themeBtnActiveBg)
		setOption(db, "radius", radius)
		setOption(db, "layoutContainerMax", layoutContainerMax)
		setOption(db, "layoutContainerPad", layoutContainerPad)
		setOption(db, "layoutColumnGap", layoutColumnGap)
		setOption(db, "layoutPagePadding", layoutPagePadding)
		setOption(db, "layoutPostPadding", layoutPostPadding)
		setOption(db, "layoutWidgetPadding", layoutWidgetPadding)

		renderSettingsPage(c, activeSection, "皮肤设置保存成功")
	})

	admin.POST("/settings", writeProtectMiddleware, func(c *gin.Context) {
		activeSection := c.DefaultPostForm("activeSection", "basic")
		title := c.PostForm("title")
		description := c.PostForm("description")
		pageSize := c.PostForm("pageSize")
		recentPostsSize := c.PostForm("recentPostsSize")
		recentCommentsSize := c.PostForm("recentCommentsSize")
		showDateArchives := c.DefaultPostForm("showDateArchives", "0")
		dateArchivesSize := strings.TrimSpace(c.PostForm("dateArchivesSize"))
		if dateArchivesSize == "" {
			dateArchivesSize = "12"
		}
		grokApiKey := c.PostForm("grokApiKey")
		aiApiUrl := c.PostForm("aiApiUrl")
		aiModel := c.PostForm("aiModel")
		aiThreshold := c.PostForm("aiThreshold")
		aiTimeoutSeconds := normalizeAITimeoutSeconds(c.PostForm("aiTimeoutSeconds"))
		aiProofreadMaxChars := normalizeAIProofreadMaxChars(c.PostForm("aiProofreadMaxChars"))
		aiProofreadMaxTokens := normalizeAIProofreadMaxTokens(c.PostForm("aiProofreadMaxTokens"))
		aiProofreadPrompt := strings.TrimSpace(c.PostForm("aiProofreadPrompt"))
		if aiProofreadPrompt == "" {
			aiProofreadPrompt = defaultAIProofreadPrompt()
		}
		aiCommentPrompt := strings.TrimSpace(c.PostForm("aiCommentPrompt"))
		if aiCommentPrompt == "" {
			aiCommentPrompt = defaultAICommentModerationPrompt()
		}
		commentAiDetection := c.DefaultPostForm("commentAiDetection", "0")
		sessionTimeout := c.PostForm("sessionTimeout")
		keywords := c.PostForm("keywords")
		footerCode := c.PostForm("footerCode")
		defaultCategory := c.PostForm("defaultCategory")
		siteUrl := c.PostForm("siteUrl")
		timezone := c.DefaultPostForm("timezone", "Asia/Shanghai")
		newAdminPath := c.PostForm("adminPath")
		frontendServiceName := strings.TrimSpace(c.PostForm("frontendServiceName"))
		adminServiceName := strings.TrimSpace(c.PostForm("adminServiceName"))
		commentAudit := c.DefaultPostForm("commentAudit", "0")
		commentFailClosed := c.DefaultPostForm("commentFailClosed", "0")
		statsBufferSize := c.PostForm("statsBufferSize")
		logRetentionDays := c.PostForm("logRetentionDays")
		commentLimitIP := c.PostForm("commentLimitIP")
		commentLimitGlobal := c.PostForm("commentLimitGlobal")
		commentsEnabled := c.DefaultPostForm("commentsEnabled", "0")
		cfRequestLimitPerMinute := strings.TrimSpace(c.PostForm("cfRequestLimitPerMinute"))
		cfApiToken := strings.TrimSpace(c.PostForm("cfApiToken"))
		cfAuthEmail := strings.TrimSpace(c.PostForm("cfAuthEmail"))
		cfZoneID := strings.TrimSpace(c.PostForm("cfZoneID"))
		cfRestoreSecurityLevel := strings.TrimSpace(c.PostForm("cfRestoreSecurityLevel"))
		cfShieldAutoDisableMinutes := strings.TrimSpace(c.PostForm("cfShieldAutoDisableMinutes"))
		cfShieldAutoBlockIP := c.DefaultPostForm("cfShieldAutoBlockIP", "0")
		backupStorageType := strings.TrimSpace(c.DefaultPostForm("backupStorageType", "local"))
		backupS3Endpoint := strings.TrimSpace(c.PostForm("backupS3Endpoint"))
		backupS3Region := strings.TrimSpace(c.PostForm("backupS3Region"))
		backupS3Bucket := strings.TrimSpace(c.PostForm("backupS3Bucket"))
		backupS3AccessKey := strings.TrimSpace(c.PostForm("backupS3AccessKey"))
		backupS3SecretKey := strings.TrimSpace(c.PostForm("backupS3SecretKey"))
		backupS3Prefix := strings.TrimSpace(c.PostForm("backupS3Prefix"))
		backupS3ForcePathStyle := c.DefaultPostForm("backupS3ForcePathStyle", "0")
		if cfRequestLimitPerMinute == "" {
			cfRequestLimitPerMinute = "1000"
		}
		if cfRestoreSecurityLevel == "" {
			cfRestoreSecurityLevel = "medium"
		}
		if cfShieldAutoDisableMinutes == "" {
			cfShieldAutoDisableMinutes = "30"
		}
		if frontendServiceName == "" {
			frontendServiceName = "blog"
		}
		if adminServiceName == "" {
			adminServiceName = "blogadmin"
		}
		frontendServiceName = strings.TrimLeft(frontendServiceName, "-")
		adminServiceName = strings.TrimLeft(adminServiceName, "-")
		backupS3DraftEndpoint := backupS3Endpoint
		backupS3DraftRegion := backupS3Region
		backupS3DraftBucket := backupS3Bucket
		backupS3DraftAccessKey := backupS3AccessKey
		backupS3DraftSecretKey := backupS3SecretKey
		backupS3DraftPrefix := backupS3Prefix
		backupS3DraftForcePathStyle := backupS3ForcePathStyle
		if backupStorageType != "s3" {
			backupS3Endpoint = ""
			backupS3Region = ""
			backupS3Bucket = ""
			backupS3AccessKey = ""
			backupS3SecretKey = ""
			backupS3Prefix = ""
			backupS3ForcePathStyle = "0"
		}

		setOption(db, "title", title)
		setOption(db, "description", description)
		setOption(db, "siteUrl", siteUrl)
		setOption(db, "timezone", timezone)
		oldAdminPath := getOption(db, "adminPath", "admin")
		setOption(db, "adminPath", newAdminPath)
		setOption(db, "frontendServiceName", frontendServiceName)
		setOption(db, "adminServiceName", adminServiceName)
		setOption(db, "pageSize", pageSize)
		setOption(db, "recentPostsSize", recentPostsSize)
		setOption(db, "recentCommentsSize", recentCommentsSize)
		setOption(db, "showDateArchives", showDateArchives)
		setOption(db, "dateArchivesSize", dateArchivesSize)
		setOption(db, "grokApiKey", grokApiKey)
		setOption(db, "aiApiUrl", aiApiUrl)
		setOption(db, "aiModel", aiModel)
		setOption(db, "aiThreshold", aiThreshold)
		setOption(db, "aiTimeoutSeconds", strconv.Itoa(aiTimeoutSeconds))
		setOption(db, "aiProofreadMaxChars", strconv.Itoa(aiProofreadMaxChars))
		setOption(db, "aiProofreadMaxTokens", strconv.Itoa(aiProofreadMaxTokens))
		setOption(db, "aiProofreadPrompt", aiProofreadPrompt)
		setOption(db, "aiCommentPrompt", aiCommentPrompt)
		setOption(db, "commentAiDetection", commentAiDetection)
		setOption(db, "sessionTimeout", sessionTimeout)
		setOption(db, "keywords", keywords)
		setOption(db, "footerCode", footerCode)
		setOption(db, "defaultCategory", defaultCategory)
		setOption(db, "commentAudit", commentAudit)
		setOption(db, "commentFailClosed", commentFailClosed)
		setOption(db, "statsBufferSize", statsBufferSize)
		setOption(db, "logRetentionDays", logRetentionDays)
		setOption(db, "commentLimitIP", commentLimitIP)
		setOption(db, "commentLimitGlobal", commentLimitGlobal)
		setOption(db, "commentsEnabled", commentsEnabled)
		setOption(db, "cfRequestLimitPerMinute", cfRequestLimitPerMinute)
		setOption(db, "cfApiToken", cfApiToken)
		setOption(db, "cfAuthEmail", cfAuthEmail)
		setOption(db, "cfZoneID", cfZoneID)
		setOption(db, "cfRestoreSecurityLevel", cfRestoreSecurityLevel)
		setOption(db, "cfShieldAutoDisableMinutes", cfShieldAutoDisableMinutes)
		setOption(db, "cfShieldAutoBlockIP", cfShieldAutoBlockIP)
		setOption(db, "backupS3Endpoint", backupS3Endpoint)
		setOption(db, "backupS3Region", backupS3Region)
		setOption(db, "backupS3Bucket", backupS3Bucket)
		setOption(db, "backupS3AccessKey", backupS3AccessKey)
		setOption(db, "backupS3SecretKey", backupS3SecretKey)
		setOption(db, "backupS3Prefix", backupS3Prefix)
		setOption(db, "backupS3ForcePathStyle", backupS3ForcePathStyle)
		setOption(db, "backupS3DraftEndpoint", backupS3DraftEndpoint)
		setOption(db, "backupS3DraftRegion", backupS3DraftRegion)
		setOption(db, "backupS3DraftBucket", backupS3DraftBucket)
		setOption(db, "backupS3DraftAccessKey", backupS3DraftAccessKey)
		setOption(db, "backupS3DraftSecretKey", backupS3DraftSecretKey)
		setOption(db, "backupS3DraftPrefix", backupS3DraftPrefix)
		setOption(db, "backupS3DraftForcePathStyle", backupS3DraftForcePathStyle)
		applyConfiguredTimezone(db)

		successMsg := "设置保存成功"
		if oldAdminPath != newAdminPath {
			successMsg = "设置保存成功，后台路径已更新（重启后生效）"
		}

		renderSettingsPage(c, activeSection, successMsg)
	})

	admin.GET("/dashboard/cloudflare-access-logs", func(c *gin.Context) {
		ip := strings.TrimSpace(c.Query("ip"))
		created, err := strconv.ParseInt(strings.TrimSpace(c.Query("created")), 10, 64)
		if ip == "" || err != nil || created <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "查询参数不完整。",
			})
			return
		}

		apiToken := strings.TrimSpace(getOption(db, "cfApiToken", ""))
		authEmail := strings.TrimSpace(getOption(db, "cfAuthEmail", ""))
		zoneID := strings.TrimSpace(getOption(db, "cfZoneID", ""))
		if apiToken == "" || zoneID == "" {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "当前系统未设置 Cloudflare API Token 或 Zone ID。",
			})
			return
		}

		logs, err := queryCloudflareAccessLogs(apiToken, authEmail, zoneID, ip, created)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":   true,
			"logs": logs,
		})
	})

	admin.POST("/dashboard/cloudflare-access-analysis", func(c *gin.Context) {
		var req struct {
			Logs []cloudflareAccessLogItem `json:"logs"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "日志参数不完整。",
			})
			return
		}
		if len(req.Logs) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ok":       true,
				"analysis": "当前没有可分析的访问记录。",
			})
			return
		}

		aiURL := strings.TrimSpace(getOption(db, "aiApiUrl", "https://api.groq.com/openai/v1/chat/completions"))
		aiKey := strings.TrimSpace(getOption(db, "grokApiKey", ""))
		aiModel := strings.TrimSpace(getOption(db, "aiModel", ""))
		analysis, err := analyzeCloudflareAttackType(aiKey, aiURL, aiModel, req.Logs)
		if err != nil {
			analysis = "AI 分析失败：" + err.Error()
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":       true,
			"analysis": analysis,
		})
	})

	admin.POST("/dashboard/cloudflare-unblock-ips", writeProtectMiddleware, func(c *gin.Context) {
		var req struct {
			LogID int64 `json:"log_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.LogID <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "日志参数不完整。",
			})
			return
		}

		var blockedIPsText string
		if err := db.QueryRow("SELECT COALESCE(blocked_ips, '') FROM go_cf_shield_logs WHERE id = ?", req.LogID).Scan(&blockedIPsText); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "未找到对应五秒盾日志。",
			})
			return
		}

		blockedRules, err := parseCloudflareBlockedRules(blockedIPsText)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": err.Error(),
			})
			return
		}
		if len(blockedRules) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ok":      true,
				"message": "当前没有需要解除的黑名单 IP。",
			})
			return
		}

		apiToken := strings.TrimSpace(getOption(db, "cfApiToken", ""))
		authEmail := strings.TrimSpace(getOption(db, "cfAuthEmail", ""))
		zoneID := strings.TrimSpace(getOption(db, "cfZoneID", ""))
		if apiToken == "" || zoneID == "" {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "当前系统未设置 Cloudflare API Token 或 Zone ID。",
			})
			return
		}

		failedRules := unblockCloudflareBlockedRules(apiToken, authEmail, zoneID, blockedRules)
		failedRulesJSON, err := json.Marshal(failedRules)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "解除结果序列化失败。",
			})
			return
		}

		if _, err := db.Exec("UPDATE go_cf_shield_logs SET blocked_ips = ? WHERE id = ?", string(failedRulesJSON), req.LogID); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "解除成功，但本地日志更新失败。",
			})
			return
		}

		if len(failedRules) > 0 {
			c.JSON(http.StatusOK, gin.H{
				"ok":          false,
				"message":     "部分 IP 解除失败。",
				"blocked_ips": failedRules,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":          true,
			"message":     "已解除这批 Cloudflare 黑名单 IP。",
			"blocked_ips": []string{},
		})
	})

	admin.POST("/settings/ai-test", writeProtectMiddleware, func(c *gin.Context) {
		apiKey := strings.TrimSpace(c.PostForm("grokApiKey"))
		apiURL := strings.TrimSpace(c.PostForm("aiApiUrl"))
		model := strings.TrimSpace(c.PostForm("aiModel"))
		timeoutSeconds := normalizeAITimeoutSeconds(c.PostForm("aiTimeoutSeconds"))
		prompt := strings.TrimSpace(c.PostForm("aiCommentPrompt"))
		if prompt == "" {
			prompt = defaultAICommentModerationPrompt()
		}
		testContent := strings.TrimSpace(c.PostForm("aiTestContent"))
		if apiKey == "" || apiURL == "" || model == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "请先填写 AI API URL、AI Model 和 AI API Key。",
			})
			return
		}
		if testContent == "" {
			testContent = "这是一条正常的测试评论，用于检测评论过滤 AI 接口是否可正常调用。"
		}

		score, err := checkSpamAITestComment(testContent, apiKey, apiURL, model, prompt, timeoutSeconds)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "调用失败：" + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"message": fmt.Sprintf("AI 接口连接正常，评论检测服务已就绪，得分：%d。", score),
			"score":   score,
		})
	})

	admin.POST("/settings/cloudflare-test", writeProtectMiddleware, func(c *gin.Context) {
		apiToken := strings.TrimSpace(c.PostForm("cfApiToken"))
		authEmail := strings.TrimSpace(c.PostForm("cfAuthEmail"))
		zoneID := strings.TrimSpace(c.PostForm("cfZoneID"))
		if apiToken == "" || zoneID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "请先填写 Cloudflare API Token 和 Zone ID。",
			})
			return
		}

		zoneName, err := testCloudflareCredentials(apiToken, authEmail, zoneID)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "检测失败：" + err.Error(),
			})
			return
		}

		msg := "Cloudflare 接口连接正常，配置已可用。"
		if zoneName != "" {
			msg = fmt.Sprintf("Cloudflare 接口连接正常，当前站点 %s 配置已可用。", zoneName)
		}
		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"message": msg,
		})
	})

	admin.POST("/settings/s3-test", writeProtectMiddleware, func(c *gin.Context) {
		if strings.TrimSpace(c.DefaultPostForm("backupStorageType", "local")) != "s3" {
			c.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "当前未选择 S3 兼容存储。",
			})
			return
		}

		cfg := backupStorageConfig{
			Endpoint:       strings.TrimSpace(c.PostForm("backupS3Endpoint")),
			Region:         strings.TrimSpace(c.PostForm("backupS3Region")),
			Bucket:         strings.TrimSpace(c.PostForm("backupS3Bucket")),
			AccessKey:      strings.TrimSpace(c.PostForm("backupS3AccessKey")),
			SecretKey:      strings.TrimSpace(c.PostForm("backupS3SecretKey")),
			Prefix:         strings.TrimSpace(c.PostForm("backupS3Prefix")),
			ForcePathStyle: c.DefaultPostForm("backupS3ForcePathStyle", "0") == "1",
		}

		if err := testS3Credentials(cfg); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ok":      false,
				"message": "检测失败：" + err.Error(),
			})
			return
		}

		msg := fmt.Sprintf("S3 接口连接正常，存储桶 %s 可读取。", cfg.Bucket)
		if prefix := cfg.NormalizedPrefix(); prefix != "" {
			msg = fmt.Sprintf("S3 接口连接正常，存储桶 %s 前缀 %s/ 可读取。", cfg.Bucket, prefix)
		}
		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"message": msg,
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

	admin.GET("/post/preview/:cid", func(c *gin.Context) {
		cid, err := strconv.Atoi(c.Param("cid"))
		if err != nil || cid <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "文章不存在"})
			return
		}

		group, _ := c.Get("userGroup")
		query := "SELECT title, text FROM typecho_contents WHERE cid=? AND type='post'"
		args := []interface{}{cid}
		if group == "visitor" {
			query += " AND status='publish'"
		}

		var title, text string
		if err := db.QueryRow(query, args...).Scan(&title, &text); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "文章不存在"})
			return
		}

		preview, err := adminRenderPostPreview(mdRenderer, title, text)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "预览生成失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "html": preview})
	})

	admin.POST("/post/preview", func(c *gin.Context) {
		preview, err := adminRenderPostContent(mdRenderer, c.PostForm("title"), c.PostForm("text"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "预览生成失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "html": preview})
	})

	admin.POST("/post/ai-proofread", writeProtectMiddleware, func(c *gin.Context) {
		text := c.PostForm("text")
		if strings.TrimSpace(text) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请先输入文章内容"})
			return
		}
		maxChars := normalizeAIProofreadMaxChars(getOption(db, "aiProofreadMaxChars", "0"))
		textChars := len([]rune(text))
		if maxChars > 0 && textChars > maxChars {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("当前文章长度为 %d 字符，超过 AI 校稿最大长度 %d 字符。", textChars, maxChars),
			})
			return
		}

		apiKey := strings.TrimSpace(getOption(db, "grokApiKey", ""))
		apiURL := strings.TrimSpace(getOption(db, "aiApiUrl", "https://api.groq.com/openai/v1/chat/completions"))
		model := strings.TrimSpace(getOption(db, "aiModel", ""))
		timeoutSeconds := normalizeAITimeoutSeconds(getOption(db, "aiTimeoutSeconds", "10"))
		if timeoutSeconds < 60 {
			timeoutSeconds = 60
		}
		prompt := strings.TrimSpace(getOption(db, "aiProofreadPrompt", defaultAIProofreadPrompt()))
		if prompt == "" {
			prompt = defaultAIProofreadPrompt()
		}
		maxTokens := normalizeAIProofreadMaxTokens(getOption(db, "aiProofreadMaxTokens", "16384"))

		proofreadText, err := proofreadPostTextWithAI(text, apiKey, apiURL, model, prompt, maxTokens, timeoutSeconds)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"success": false, "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "text": proofreadText})
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

		rows, err := db.Query(`
			SELECT c.coid, c.cid, c.parent, c.author, c.text, c.status, c.created, COALESCE(p.title, '')
			FROM typecho_comments c
			LEFT JOIN typecho_contents p ON p.cid = c.cid AND p.type = 'post'
			ORDER BY c.created DESC, c.coid DESC
			LIMIT ? OFFSET ?`, pageSize, offset)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		defer rows.Close()

		var comments []map[string]interface{}
		for rows.Next() {
			var coid, cid, parent int
			var author, text, status, postTitle string
			var created int64
			rows.Scan(&coid, &cid, &parent, &author, &text, &status, &created, &postTitle)
			comments = append(comments, map[string]interface{}{
				"Coid":      coid,
				"Cid":       cid,
				"Parent":    parent,
				"Author":    author,
				"Text":      text,
				"Status":    status,
				"Created":   time.Unix(created, 0).Format("2006-01-02 15:04"),
				"PostTitle": postTitle,
			})
		}

		for _, comment := range comments {
			if parent, ok := comment["Parent"].(int); ok && parent > 0 {
				var parentAuthor string
				db.QueryRow("SELECT author FROM typecho_comments WHERE coid=?", parent).Scan(&parentAuthor)
				if parentAuthor != "" {
					comment["ParentAuthor"] = parentAuthor
				}
			}
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

	admin.GET("/attachments", func(c *gin.Context) {
		pageStr := c.DefaultQuery("page", "1")
		searchQuery := strings.TrimSpace(c.Query("q"))
		page := 1
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
		pageSize := 10

		group, _ := c.Get("userGroup")

		querySQL := `
			SELECT a.cid, a.title, a.text, a.created, a.parent, COALESCE(p.title, '')
			FROM typecho_contents a
			LEFT JOIN typecho_contents p ON p.cid = a.parent AND p.type='post'
			WHERE a.type='attachment'`
		var queryArgs []interface{}
		if group == "visitor" {
			querySQL += " AND p.status='publish'"
		}
		if searchQuery != "" {
			querySQL += " AND p.title LIKE ?"
			queryArgs = append(queryArgs, "%"+searchQuery+"%")
		}
		querySQL += `
			ORDER BY a.created DESC, a.cid DESC`
		rows, err := db.Query(querySQL, queryArgs...)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		defer rows.Close()

		type attachmentItem struct {
			Cid      int
			FileName string
			Path     string
			IsImage  bool
			Created  string
		}
		type attachmentGroup struct {
			ParentCid     int
			PostTitle     string
			LatestCreated int64
			Created       string
			Items         []attachmentItem
		}

		groupMap := make(map[string]*attachmentGroup)
		groupOrder := make([]string, 0)
		for rows.Next() {
			var cid, parent int
			var relPathTitle, relPathText, postTitle string
			var created int64
			rows.Scan(&cid, &relPathTitle, &relPathText, &created, &parent, &postTitle)
			relPath := resolveAttachmentPath(relPathTitle, relPathText)
			displayName := filepath.Base(relPath)
			if displayName == "." || displayName == "/" || displayName == "" {
				displayName = filepath.Base(relPathTitle)
			}
			if postTitle == "" {
				postTitle = "未引用"
			}
			ext := strings.ToLower(filepath.Ext(relPath))
			isImage := ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".webp" || ext == ".bmp" || ext == ".svg"

			groupKey := fmt.Sprintf("%d:%s", parent, postTitle)
			currentGroup, exists := groupMap[groupKey]
			if !exists {
				currentGroup = &attachmentGroup{
					ParentCid:     parent,
					PostTitle:     postTitle,
					LatestCreated: created,
					Created:       time.Unix(created, 0).Format("2006-01-02 15:04"),
					Items:         make([]attachmentItem, 0),
				}
				groupMap[groupKey] = currentGroup
				groupOrder = append(groupOrder, groupKey)
			}

			if created > currentGroup.LatestCreated {
				currentGroup.LatestCreated = created
				currentGroup.Created = time.Unix(created, 0).Format("2006-01-02 15:04")
			}

			currentGroup.Items = append(currentGroup.Items, attachmentItem{
				Cid:      cid,
				FileName: displayName,
				Path:     relPath,
				IsImage:  isImage,
				Created:  time.Unix(created, 0).Format("2006-01-02 15:04"),
			})
		}

		attachments := make([]attachmentGroup, 0, len(groupOrder))
		for _, key := range groupOrder {
			attachments = append(attachments, *groupMap[key])
		}

		total := len(attachments)
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages == 0 {
			totalPages = 1
		}
		if page > totalPages {
			page = totalPages
		}

		start := (page - 1) * pageSize
		end := start + pageSize
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		attachments = attachments[start:end]

		username, _ := c.Get("username")
		c.HTML(http.StatusOK, "admin_attachments.html", gin.H{
			"Username":    username,
			"UserGroup":   group,
			"Attachments": attachments,
			"SearchQuery": searchQuery,
			"Tab":         "attachments",
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

	admin.POST("/comment/edit/:coid", writeProtectMiddleware, func(c *gin.Context) {
		coid := c.Param("coid")
		author := strings.TrimSpace(c.PostForm("author"))
		content := strings.TrimSpace(c.PostForm("text"))
		if author == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "作者不能为空"})
			return
		}
		if content == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "评论内容不能为空"})
			return
		}

		result, err := db.Exec("UPDATE typecho_comments SET author=?, text=? WHERE coid=?", author, content, coid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
			return
		}
		if rows, _ := result.RowsAffected(); rows == 0 {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "评论不存在"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "评论已更新"})
	})

	admin.POST("/comment/reply/:coid", writeProtectMiddleware, func(c *gin.Context) {
		coid := c.Param("coid")
		content := strings.TrimSpace(c.PostForm("text"))
		if content == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "回复内容不能为空"})
			return
		}

		var cid, ownerId int
		if err := db.QueryRow("SELECT cid, ownerId FROM typecho_comments WHERE coid=?", coid).Scan(&cid, &ownerId); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "评论不存在"})
			return
		}

		username, _ := c.Get("username")
		var authorId int
		var authorName, screenName string
		db.QueryRow("SELECT uid, name, COALESCE(screenName, '') FROM typecho_users WHERE name=?", username).Scan(&authorId, &authorName, &screenName)
		if screenName == "" {
			screenName = authorName
		}

		now := time.Now().Unix()
		_, err := db.Exec(`
			INSERT INTO typecho_comments (cid, created, author, authorId, ownerId, ip, agent, text, type, status, parent)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'comment', 'approved', ?)`,
			cid, now, screenName, authorId, ownerId, c.ClientIP(), c.Request.UserAgent(), content, coid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
			return
		}

		db.Exec("UPDATE typecho_contents SET commentsNum = commentsNum + 1 WHERE cid = ?", cid)
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "回复已发布"})
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

		// Check if this is an AJAX request
		isAjax := c.GetHeader("X-Requested-With") == "XMLHttpRequest" ||
			strings.Contains(c.GetHeader("Accept"), "application/json")

		if midStr == "" || midStr == "0" {
			res, err := db.Exec("INSERT INTO typecho_metas (name, slug, type, description, count, \"order\", parent) VALUES (?, ?, 'category', '', 0, ?, 0)", name, slug, order)
			if err != nil {
				if isAjax {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
				} else {
					c.String(500, err.Error())
				}
				return
			}
			lastId, _ := res.LastInsertId()
			db.Exec("INSERT INTO go_category_settings (mid, show_on_home, is_offline) VALUES (?, ?, ?)", lastId, showOnHome, isOffline)
		} else {
			_, err := db.Exec("UPDATE typecho_metas SET name=?, slug=?, \"order\"=? WHERE mid=?", name, slug, order, midStr)
			if err != nil {
				if isAjax {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
				} else {
					c.String(500, err.Error())
				}
				return
			}
			db.Exec("INSERT INTO go_category_settings (mid, show_on_home, is_offline) VALUES (?, ?, ?) ON CONFLICT(mid) DO UPDATE SET show_on_home=excluded.show_on_home, is_offline=excluded.is_offline", midStr, showOnHome, isOffline)
		}

		if isAjax {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "保存成功"})
		} else {
			c.Redirect(http.StatusFound, ""+adminPath+"/categories")
		}
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
			rows, err = db.Query("SELECT uid, name, COALESCE(screenName,''), COALESCE(mail,''), COALESCE(url,''), COALESCE(\"group\",'visitor'), logged FROM typecho_users WHERE name=? ORDER BY uid ASC", username)
		} else {
			rows, err = db.Query("SELECT uid, name, COALESCE(screenName,''), COALESCE(mail,''), COALESCE(url,''), COALESCE(\"group\",'visitor'), logged FROM typecho_users ORDER BY uid ASC")
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
		err := db.QueryRow("SELECT name, COALESCE(screenName,''), COALESCE(mail,''), COALESCE(url,''), COALESCE(\"group\",'visitor') FROM typecho_users WHERE uid=?", uid).
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
	renderBackupsPage := func(c *gin.Context, successMsg, errorMsg string) {
		username, _ := c.Get("username")
		adminPath, _ := c.Get("adminPath")
		storageCfg := getBackupStorageConfig(db)
		scheduleCfg := getBackupScheduleConfig(db)
		scheduleHour, scheduleMinute := splitBackupScheduleTime(scheduleCfg.DailyTime)

		localBackups, localErr := listLocalBackupEntries()
		remoteBackups, remoteErr := listS3BackupEntries(storageCfg)
		backups := append(localBackups, remoteBackups...)

		sortBackupEntriesByTimeDesc(backups)

		backupMutex.Lock()
		running := isBackingUp
		lastResult := backupLastResult
		lastResultIsErr := backupLastResultIsErr
		backupMutex.Unlock()

		consumeLastResult := false
		if successMsg == "" && errorMsg == "" {
			switch c.Query("msg") {
			case "created":
				if running {
					successMsg = "备份任务已启动，正在后台处理中..."
				} else if lastResult != "" {
					if lastResultIsErr {
						errorMsg = lastResult
					} else {
						successMsg = lastResult
					}
					consumeLastResult = true
				} else {
					successMsg = "备份任务已完成"
				}
			case "deleted":
				successMsg = "备份已删除"
			case "vacuumed":
				successMsg = "数据库压缩完成，无用空间已释放"
			case "error":
				errorMsg = "数据库压缩失败，请检查服务日志。"
			default:
				if !running && lastResult != "" {
					if lastResultIsErr {
						errorMsg = lastResult
					} else {
						successMsg = lastResult
					}
					consumeLastResult = true
				}
			}
		}

		if consumeLastResult {
			backupMutex.Lock()
			if backupLastResult == lastResult {
				backupLastResult = ""
				backupLastResultIsErr = false
			}
			backupMutex.Unlock()
		}

		if localErr != nil {
			if errorMsg != "" {
				errorMsg += "；"
			}
			errorMsg += "本地备份目录读取失败。"
		}
		if remoteErr != nil {
			if errorMsg != "" {
				errorMsg += "；"
			}
			errorMsg += remoteErr.Error()
		}

		c.HTML(http.StatusOK, "admin_backups.html", gin.H{
			"Username":                     username,
			"Backups":                      backups,
			"Tab":                          "backups",
			"AdminPath":                    adminPath,
			"SuccessMessage":               successMsg,
			"ErrorMessage":                 errorMsg,
			"IsBackingUp":                  running,
			"BackupStorageMode":            map[bool]string{true: "S3 兼容存储", false: "本地目录"}[storageCfg.Enabled()],
			"BackupStorageSummary":         storageCfg.Summary(),
			"BackupStorageEnabled":         storageCfg.Enabled(),
			"BackupStorageFallback":        storageCfg.Enabled(),
			"BackupScheduleEnabled":        scheduleCfg.Enabled,
			"BackupScheduleTime":           scheduleCfg.DailyTime,
			"BackupScheduleHour":           scheduleHour,
			"BackupScheduleMinute":         scheduleMinute,
			"BackupScheduleHourOptions":    buildTimeSelectOptions(0, 23, scheduleHour),
			"BackupScheduleMinuteOptions":  buildTimeSelectOptions(0, 59, scheduleMinute),
			"BackupScheduleRetentionCount": scheduleCfg.RetentionCount,
			"BackupScheduleWeekdays":       scheduleCfg.Weekdays,
			"BackupScheduleWeekdayLabels":  scheduleCfg.WeekdayLabels,
			"BackupScheduleWeekdayOptions": backupScheduleWeekdayOptions(scheduleCfg.Weekdays),
			"BackupScheduleLastRunDate":    scheduleCfg.LastRunDate,
			"BackupScheduleSummary":        scheduleCfg.Summary(),
		})
	}

	admin.GET("/backups", func(c *gin.Context) {
		renderBackupsPage(c, "", "")
	})

	admin.POST("/backups/create", writeProtectMiddleware, func(c *gin.Context) {
		if err := runBackupJob(db, "manual"); err != nil {
			renderBackupsPage(c, "", "备份任务正在进行中，请在结束后再试。")
			return
		}
		c.Redirect(http.StatusFound, adminPath+"/backups?msg=created")
	})

	admin.POST("/backups/schedule", writeProtectMiddleware, func(c *gin.Context) {
		enabled := c.DefaultPostForm("backupScheduleEnabled", "0") == "1"
		rawHour := strings.TrimSpace(c.PostForm("backupScheduleHour"))
		rawMinute := strings.TrimSpace(c.PostForm("backupScheduleMinute"))
		rawDailyTime := fmt.Sprintf("%s:%s", rawHour, rawMinute)
		if !isValidBackupScheduleTime(rawDailyTime) {
			renderBackupsPage(c, "", "每日备份时间格式无效，请按 24 小时制填写。")
			return
		}
		dailyTime := normalizeBackupScheduleTime(rawDailyTime)
		retentionRaw := strings.TrimSpace(c.PostForm("backupScheduleRetentionCount"))
		retentionCount, err := strconv.Atoi(retentionRaw)
		if err != nil || retentionCount < 1 || retentionCount > 365 {
			renderBackupsPage(c, "", "保留备份个数必须填写 1 到 365 之间的整数。")
			return
		}
		weekdays := normalizeBackupScheduleWeekdays(c.PostFormArray("backupScheduleWeekdays"))

		setGoOnlyOption(db, "backupScheduleEnabled", map[bool]string{true: "1", false: "0"}[enabled])
		setGoOnlyOption(db, "backupScheduleTime", dailyTime)
		setGoOnlyOption(db, "backupScheduleRetentionCount", strconv.Itoa(retentionCount))
		weekdayTexts := make([]string, 0, len(weekdays))
		for _, day := range weekdays {
			weekdayTexts = append(weekdayTexts, strconv.Itoa(day))
		}
		setGoOnlyOption(db, "backupScheduleWeekdays", strings.Join(weekdayTexts, ","))

		renderBackupsPage(c, "定时备份设置已保存", "")
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

		switch c.DefaultPostForm("storage", "local") {
		case "local":
			path := filepath.Join("backups", safeFilename)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				renderBackupsPage(c, "", "本地备份删除失败。")
				return
			}
		case "s3":
			storageCfg := getBackupStorageConfig(db)
			if !storageCfg.Enabled() {
				renderBackupsPage(c, "", "S3 配置未填写完整，无法删除远端备份。")
				return
			}
			if err := deleteBackupFromS3(storageCfg, safeFilename); err != nil {
				renderBackupsPage(c, "", err.Error())
				return
			}
		default:
			c.String(400, "非法操作：未知备份存储类型")
			return
		}

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
		frontendServiceName := strings.TrimSpace(getOption(db, "frontendServiceName", "blog"))
		if frontendServiceName == "" {
			frontendServiceName = "blog"
		}
		adminServiceName := strings.TrimSpace(getOption(db, "adminServiceName", "blogadmin"))
		if adminServiceName == "" {
			adminServiceName = "blogadmin"
		}

		// 先重启前台 blog 服务
		go func() {
			// 稍微延迟一下，确保响应能发出
			time.Sleep(1 * time.Second)
			log.Println("收到重启请求，准备重启服务...")

			// 重启前台服务
			cmdBlog := exec.Command("systemctl", "restart", frontendServiceName)
			if err := cmdBlog.Run(); err != nil {
				log.Printf("重启前台服务失败 (%s): %v", frontendServiceName, err)
			} else {
				log.Printf("前台服务重启成功: %s", frontendServiceName)
			}

			// 重启后台服务 (后台自己)
			// 注意：这会导致当前进程退出，systemctl 会自动重启它
			cmdAdmin := exec.Command("systemctl", "restart", adminServiceName)
			if err := cmdAdmin.Run(); err != nil {
				log.Printf("重启后台服务失败 (%s): %v", adminServiceName, err)
			}
		}()

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": fmt.Sprintf("服务重启指令已发送：%s、%s，请稍等片刻后刷新页面。", frontendServiceName, adminServiceName),
		})
	})

	admin.GET("/edit/:cid", func(c *gin.Context) {
		cid := c.Param("cid")
		aiProofreadEnabled := strings.TrimSpace(getOption(db, "grokApiKey", "")) != "" &&
			strings.TrimSpace(getOption(db, "aiApiUrl", "https://api.groq.com/openai/v1/chat/completions")) != "" &&
			strings.TrimSpace(getOption(db, "aiModel", "")) != ""
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
				"Username":           username,
				"UserGroup":          group,
				"Post":               post,
				"IsNew":              false,
				"Attachments":        attachments,
				"Tab":                "posts",
				"Categories":         categories,
				"AiProofreadEnabled": aiProofreadEnabled,
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
				"Username":           username,
				"UserGroup":          group,
				"Post":               post,
				"IsNew":              true,
				"Attachments":        nil,
				"Tab":                "posts",
				"Categories":         categories,
				"AiProofreadEnabled": aiProofreadEnabled,
			})
		}
	})

	admin.POST("/attachment/delete/:cid", writeProtectMiddleware, func(c *gin.Context) {
		attCid := c.Param("cid")
		parentCid := c.Query("parent")
		backTarget := c.Query("back")

		var relPathTitle, relPathText string
		var parentFromDB int
		err := db.QueryRow("SELECT title, text, parent FROM typecho_contents WHERE cid=? AND type='attachment'", attCid).Scan(&relPathTitle, &relPathText, &parentFromDB)
		relPath := resolveAttachmentPath(relPathTitle, relPathText)
		if err == nil && relPath != "" {
			localSubPath := strings.TrimPrefix(relPath, "/blog/")
			if strings.HasPrefix(localSubPath, "usr/uploads/") && !strings.Contains(localSubPath, "..") {
				absPath := filepath.Join(".", localSubPath)
				os.Remove(absPath)
			}
		}

		cleanupAttachmentReference(attCid)
		db.Exec("DELETE FROM typecho_contents WHERE cid=?", attCid)

		if backTarget == "attachments" {
			c.Redirect(http.StatusFound, adminPath+"/attachments")
			return
		}
		if parentCid == "" && parentFromDB > 0 {
			parentCid = fmt.Sprintf("%d", parentFromDB)
		}
		if parentCid == "" {
			c.Redirect(http.StatusFound, adminPath+"/attachments")
			return
		}
		c.Redirect(http.StatusFound, adminPath+"/edit/"+parentCid)
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
		var attachmentID int64
		if parentCid != "" {
			result, err := db.Exec("INSERT INTO typecho_contents (title, slug, created, modified, text, authorId, type, status, parent) VALUES (?, ?, ?, ?, ?, 1, 'attachment', 'publish', ?)",
				relPath, fileName, now.Unix(), now.Unix(), "", parentCid)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": 0, "message": "附件登记失败"})
				return
			}
			attachmentID, _ = result.LastInsertId()
		}

		c.JSON(http.StatusOK, gin.H{
			"success": 1,
			"message": "上传成功",
			"url":     relPath,
			"cid":     attachmentID,
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

func applyConfiguredTimezone(db *sql.DB) {
	tz := strings.TrimSpace(getOption(db, "timezone", "Asia/Shanghai"))
	if tz == "" {
		tz = "Asia/Shanghai"
	}
	if tz == "system" {
		time.Local = systemTimeLocation
		return
	}
	loc, ok := loadTimezoneLocation(tz)
	if !ok {
		log.Printf("Invalid timezone %q, fallback to Asia/Shanghai", tz)
		loc = time.FixedZone("GMT+8", 8*60*60)
	}
	time.Local = loc
}

func loadTimezoneLocation(tz string) (*time.Location, bool) {
	loc, err := time.LoadLocation(tz)
	if err == nil {
		return loc, true
	}
	seconds, convErr := strconv.Atoi(tz)
	if convErr != nil {
		return nil, false
	}
	return time.FixedZone(formatGMTOffset(seconds), seconds), true
}

func formatGMTOffset(offsetSeconds int) string {
	sign := "+"
	if offsetSeconds < 0 {
		sign = "-"
		offsetSeconds = -offsetSeconds
	}
	hours := offsetSeconds / 3600
	minutes := (offsetSeconds % 3600) / 60
	return fmt.Sprintf("GMT%s%02d:%02d", sign, hours, minutes)
}

func normalizeTimezoneOption(tz string) string {
	switch strings.TrimSpace(tz) {
	case "Asia/Shanghai", "UTC", "system":
		return strings.TrimSpace(tz)
	case "28800":
		return "Asia/Shanghai"
	default:
		return "Asia/Shanghai"
	}
}

func stripThinkingOutput(content string) string {
	thinkBlockRE := regexp.MustCompile(`(?is)<think\b[^>]*>.*?</think>`)
	codeFenceRE := regexp.MustCompile("(?is)```(?:[a-z0-9_+-]+)?\\s*(.*?)\\s*```")

	cleaned := thinkBlockRE.ReplaceAllString(content, " ")
	cleaned = codeFenceRE.ReplaceAllString(cleaned, "$1")

	return strings.TrimSpace(cleaned)
}

func stripThinkingBlocks(content string) string {
	thinkBlockRE := regexp.MustCompile(`(?is)<think\b[^>]*>.*?</think>`)
	return strings.TrimSpace(thinkBlockRE.ReplaceAllString(content, " "))
}

func compactAIText(content string) string {
	cleaned := stripThinkingOutput(content)
	if idx := strings.IndexAny(cleaned, "\r\n"); idx >= 0 {
		cleaned = cleaned[:idx]
	}
	return strings.TrimSpace(cleaned)
}

func extractSpamScore(content string) (int, bool) {
	cleaned := stripThinkingOutput(content)
	scoreRE := regexp.MustCompile(`\b([0-9])\b`)
	match := scoreRE.FindStringSubmatch(cleaned)
	if len(match) < 2 {
		return 0, false
	}

	score, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}

	return score, true
}

func callAIChatCompletionText(apiKey, apiURL string, requestData map[string]interface{}) (string, error) {
	return callAIChatCompletionTextWithTimeout(apiKey, apiURL, requestData, 10)
}

func callAIChatCompletionTextWithTimeout(apiKey, apiURL string, requestData map[string]interface{}, timeoutSeconds int) (string, error) {
	return callAIChatCompletionTextInternal(apiKey, apiURL, requestData, timeoutSeconds, true)
}

func callAIChatCompletionFullTextWithTimeout(apiKey, apiURL string, requestData map[string]interface{}, timeoutSeconds int) (string, error) {
	return callAIChatCompletionTextInternal(apiKey, apiURL, requestData, timeoutSeconds, false)
}

func callAIChatCompletionTextInternal(apiKey, apiURL string, requestData map[string]interface{}, timeoutSeconds int, compact bool) (string, error) {
	if apiKey == "" || apiURL == "" {
		return "", fmt.Errorf("AI 配置缺失：请填写 AI API URL 和 AI API Key")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("AI 请求组装失败: %w", err)
	}

	client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("AI 请求创建失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI 请求发送失败: %w", err)
	}
	defer resp.Body.Close()

	bodyLimit := int64(4096)
	if !compact {
		bodyLimit = 4 * 1024 * 1024
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	if resp.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(body))
		if detail != "" {
			return "", fmt.Errorf("AI 接口返回状态 %d: %s", resp.StatusCode, detail)
		}
		return "", fmt.Errorf("AI 接口返回状态 %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
		OutputText string `json:"output_text"`
		Text       string `json:"text"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("AI 响应解析失败: %w; 原始返回: %s", err, strings.TrimSpace(string(body)))
	}

	content := ""
	if len(result.Choices) > 0 {
		if s, ok := result.Choices[0].Message.Content.(string); ok {
			content = strings.TrimSpace(s)
		}
		if content == "" {
			content = strings.TrimSpace(result.Choices[0].Text)
		}
	}
	if content == "" {
		content = strings.TrimSpace(result.OutputText)
	}
	if content == "" {
		content = strings.TrimSpace(result.Text)
	}
	if content == "" {
		return "", fmt.Errorf("AI 响应为空，原始返回: %s", strings.TrimSpace(string(body)))
	}

	if compact {
		return compactAIText(content), nil
	}
	return stripThinkingBlocks(content), nil
}

func defaultAIProofreadPrompt() string {
	return "你帮我处理一下现在正在撰写的文章内容，只整理排版、段落、错别字和标点，在不改变原意、语气、观点和事实的前提下适当优化自然语言表达与阅读流畅度，但禁止润色、扩写、缩写、重写观点或加入任何新内容。如果发现 Markdown 语法、链接、图片、代码块、HTML 或 Typecho 标签，务必保持原样，包括字符内容、顺序和所在位置，不要改写、移动、删除或补全。直接输出整理后的全文。"
}

func defaultAICommentModerationPrompt() string {
	return "你是博客评论安全审核助手。请判断用户提交的评论是否属于垃圾评论、广告推广、无意义内容、政治内容、宗教内容，或包含 SQL 注入、XSS、命令注入、恶意脚本、漏洞利用、网络攻击载荷等技术攻击内容，以及攻击性、冒犯性、侮辱性言辞、人身攻击、辱骂、挑衅或威胁性表达。请只返回 0 到 9 的单个整数，不要解释，不要附加任何其他字符或内容：0 表示安全，例如正常的技术讨论、编程、服务器相关交流或普通意见表达；5 表示可疑或需要人工复核，例如语义不完整、内容明显异常、疑似引战、轻度冒犯、阴阳怪气、带挑衅意味，或上下文不足暂时无法确认是否恶意；9 表示确认属于垃圾评论、广告推广、政治内容、宗教内容、无意义内容、技术攻击内容，或包含攻击性、冒犯性、侮辱性言辞、人身攻击、辱骂、挑衅或威胁性表达。如果输入内容包含俄文、阿拉伯文或其他非中文、非英文内容，请评分为 9。"
}

func proofreadPostTextWithAI(text string, apiKey string, apiURL string, model string, prompt string, maxTokens int, timeoutSeconds int) (string, error) {
	if apiKey == "" || apiURL == "" || model == "" {
		return "", fmt.Errorf("AI 校稿配置缺失：请填写 AI API URL、AI Model 和 AI API Key")
	}
	if strings.TrimSpace(prompt) == "" {
		prompt = defaultAIProofreadPrompt()
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	if maxTokens <= 0 {
		maxTokens = 16384
	}

	messages := []map[string]string{
		{"role": "system", "content": prompt},
		{"role": "user", "content": text},
	}

	var lastErr error
	for _, requestMaxTokens := range aiProofreadTokenFallbacks(maxTokens) {
		requestData := map[string]interface{}{
			"model":       model,
			"messages":    messages,
			"max_tokens":  requestMaxTokens,
			"temperature": 0,
		}

		content, err := callAIChatCompletionFullTextWithTimeout(apiKey, apiURL, requestData, timeoutSeconds)
		if err == nil {
			if strings.TrimSpace(content) == "" {
				return "", fmt.Errorf("AI 校稿结果为空")
			}
			return content, nil
		}
		lastErr = err
		if !isAITokenLimitError(err) {
			break
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("AI 校稿失败: %w", lastErr)
	}
	return "", fmt.Errorf("AI 校稿失败")
}

func isAITokenLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "max_tokens") ||
		strings.Contains(msg, "max token") ||
		strings.Contains(msg, "maximum token") ||
		strings.Contains(msg, "context length") ||
		strings.Contains(msg, "too many tokens")
}

func checkSpamAITestComment(words string, apiKey string, apiURL string, model string, prompt string, timeoutSeconds int) (int, error) {
	if apiKey == "" || apiURL == "" || model == "" {
		return 0, fmt.Errorf("AI 检测配置缺失：请填写 AI API URL、AI Model 和 AI API Key")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	if strings.TrimSpace(prompt) == "" {
		prompt = defaultAICommentModerationPrompt()
	}

	requestData := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": prompt},
			{"role": "user", "content": words},
		},
		"max_tokens":  512,
		"temperature": 0,
	}

	content, err := callAIChatCompletionTextWithTimeout(apiKey, apiURL, requestData, timeoutSeconds)
	if err != nil {
		return 0, fmt.Errorf("AI 检测失败: %w", err)
	}
	score, ok := extractSpamScore(content)
	if !ok {
		return 0, fmt.Errorf("AI 检测响应格式不符合预期：%s", content)
	}

	return score, nil
}

func analyzeCloudflareAttackType(apiKey, apiURL, model string, logs []cloudflareAccessLogItem) (string, error) {
	if apiKey == "" || apiURL == "" || model == "" {
		return "未配置 AI，未生成攻击类型说明。", nil
	}
	if len(logs) == 0 {
		return "当前没有可分析的访问记录。", nil
	}

	var builder strings.Builder
	builder.WriteString("根据以下 Cloudflare 访问记录判断最可能的攻击类型。")
	builder.WriteString("只输出正文 content，输出4到8个汉字，不要解释，不要分点。\n\n记录：\n")
	for i, logItem := range logs {
		url := strings.TrimSpace(logItem.URL)
		if len(url) > 220 {
			url = url[:220]
		}
		builder.WriteString(fmt.Sprintf("%d. %s %s %d %s\n", i+1, logItem.Datetime, logItem.Method, logItem.Status, url))
	}

	requestData := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "你是网站安全分析助手，只输出正文 content 里的中文短语，不要解释。"},
			{"role": "user", "content": builder.String()},
		},
		"max_tokens":  4096,
		"temperature": 0,
	}

	content, err := callAIChatCompletionText(apiKey, apiURL, requestData)
	if err != nil {
		return "", err
	}
	if content == "" {
		return "", fmt.Errorf("AI 攻击类型说明为空")
	}
	return content, nil
}

func parseCloudflareBlockedRules(value string) ([]cfBlockedIPRule, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return []cfBlockedIPRule{}, nil
	}

	var rules []cfBlockedIPRule
	if err := json.Unmarshal([]byte(value), &rules); err != nil {
		return nil, fmt.Errorf("黑名单 IP 数据格式错误")
	}

	cleaned := make([]cfBlockedIPRule, 0, len(rules))
	for _, rule := range rules {
		rule.IP = strings.TrimSpace(rule.IP)
		rule.RuleID = strings.TrimSpace(rule.RuleID)
		if rule.IP == "" || rule.RuleID == "" {
			return nil, fmt.Errorf("黑名单 IP 数据缺少规则 ID")
		}
		cleaned = append(cleaned, rule)
	}
	return cleaned, nil
}

func unblockCloudflareBlockedRules(apiToken, authEmail, zoneID string, rules []cfBlockedIPRule) []cfBlockedIPRule {
	failedRules := make([]cfBlockedIPRule, 0)
	for _, rule := range rules {
		if err := deleteCloudflareAccessRule(apiToken, authEmail, zoneID, rule.RuleID); err != nil {
			log.Printf("Cloudflare 五秒盾解除黑名单 IP 失败: %s: %v", rule.IP, err)
			failedRules = append(failedRules, rule)
		} else {
			log.Printf("Cloudflare 五秒盾已解除黑名单 IP: %s", rule.IP)
		}
	}
	return failedRules
}

func deleteCloudflareAccessRule(apiToken, authEmail, zoneID, ruleID string) error {
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules/%s", zoneID, ruleID)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("构建 Cloudflare 黑名单解除请求失败: %w", err)
	}
	setCloudflareAuthHeaders(req, apiToken, authEmail)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare 黑名单解除请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare 黑名单解除返回状态 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var apiResp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if !apiResp.Success {
			if len(apiResp.Errors) > 0 && apiResp.Errors[0].Message != "" {
				return fmt.Errorf("Cloudflare 黑名单解除错误: %s", apiResp.Errors[0].Message)
			}
			return fmt.Errorf("Cloudflare 黑名单解除失败: %s", strings.TrimSpace(string(body)))
		}
	}
	return nil
}

func setCloudflareAuthHeaders(req *http.Request, apiToken, authEmail string) {
	if authEmail != "" {
		req.Header.Set("X-Auth-Email", authEmail)
		req.Header.Set("X-Auth-Key", apiToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	req.Header.Set("Content-Type", "application/json")
}

func queryCloudflareAccessLogs(apiToken, authEmail, zoneID, ip string, created int64) ([]cloudflareAccessLogItem, error) {
	startTime := time.Unix(created, 0).UTC()
	start := startTime.Format(time.RFC3339)
	end := startTime.Add(24 * time.Hour).Format(time.RFC3339)
	query := `query GetCloudflareAccessLogs($zoneTag: string, $filter: filter) {
		viewer {
			zones(filter: { zoneTag: $zoneTag }) {
				logs: httpRequestsAdaptive(limit: 20, orderBy: [datetime_ASC], filter: $filter) {
					datetime
					clientRequestHTTPHost
					clientRequestHTTPMethodName
					clientRequestPath
					clientRequestQuery
					clientRequestScheme
					edgeResponseStatus
				}
			}
		}
	}`
	payload, _ := json.Marshal(map[string]interface{}{
		"query": query,
		"variables": map[string]interface{}{
			"zoneTag": zoneID,
			"filter": map[string]interface{}{
				"AND": []map[string]interface{}{
					{"datetime_geq": start, "datetime_leq": end},
					{"clientIP": ip},
					{"requestSource": "eyeball"},
				},
			},
		},
	})

	req, err := http.NewRequest(http.MethodPost, "https://api.cloudflare.com/client/v4/graphql", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("构建 Cloudflare 查询失败: %w", err)
	}
	if authEmail != "" {
		req.Header.Set("X-Auth-Email", authEmail)
		req.Header.Set("X-Auth-Key", apiToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare 查询失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Cloudflare 返回状态 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var apiResp struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Logs []struct {
						Datetime                    string `json:"datetime"`
						ClientRequestHTTPHost       string `json:"clientRequestHTTPHost"`
						ClientRequestHTTPMethodName string `json:"clientRequestHTTPMethodName"`
						ClientRequestPath           string `json:"clientRequestPath"`
						ClientRequestQuery          string `json:"clientRequestQuery"`
						ClientRequestScheme         string `json:"clientRequestScheme"`
						EdgeResponseStatus          int    `json:"edgeResponseStatus"`
					} `json:"logs"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("Cloudflare 查询返回解析失败")
	}
	if len(apiResp.Errors) > 0 {
		if apiResp.Errors[0].Message != "" {
			return nil, fmt.Errorf("Cloudflare 查询错误: %s", apiResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare 查询失败")
	}
	if len(apiResp.Data.Viewer.Zones) == 0 {
		return []cloudflareAccessLogItem{}, nil
	}

	logs := make([]cloudflareAccessLogItem, 0, len(apiResp.Data.Viewer.Zones[0].Logs))
	for _, row := range apiResp.Data.Viewer.Zones[0].Logs {
		scheme := strings.TrimSpace(row.ClientRequestScheme)
		if scheme == "" {
			scheme = "https"
		}
		requestURL := strings.TrimSpace(row.ClientRequestPath)
		host := strings.TrimSpace(row.ClientRequestHTTPHost)
		if host != "" {
			requestURL = scheme + "://" + host + requestURL
		}
		if strings.TrimSpace(row.ClientRequestQuery) != "" {
			requestURL += "?" + strings.TrimSpace(row.ClientRequestQuery)
		}

		datetime := row.Datetime
		if parsed, err := time.Parse(time.RFC3339, row.Datetime); err == nil {
			datetime = parsed.In(systemTimeLocation).Format("2006-01-02 15:04:05")
		}

		logs = append(logs, cloudflareAccessLogItem{
			Datetime: datetime,
			Method:   row.ClientRequestHTTPMethodName,
			URL:      requestURL,
			Status:   row.EdgeResponseStatus,
		})
	}

	return logs, nil
}

func testCloudflareCredentials(apiToken, authEmail, zoneID string) (string, error) {
	endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s", zoneID)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("构建 Cloudflare 请求失败: %w", err)
	}

	if authEmail != "" {
		req.Header.Set("X-Auth-Email", authEmail)
		req.Header.Set("X-Auth-Key", apiToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Cloudflare 请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Cloudflare 返回状态 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var apiResp struct {
		Success bool `json:"success"`
		Result  struct {
			Name string `json:"name"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("Cloudflare 返回解析失败")
	}
	if !apiResp.Success {
		if len(apiResp.Errors) > 0 && apiResp.Errors[0].Message != "" {
			return "", fmt.Errorf("Cloudflare 返回错误: %s", apiResp.Errors[0].Message)
		}
		return "", fmt.Errorf("Cloudflare 返回失败")
	}

	return strings.TrimSpace(apiResp.Result.Name), nil
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

func normalizeAITimeoutSeconds(value string) int {
	timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || timeoutSeconds <= 0 {
		return 10
	}
	return timeoutSeconds
}

func normalizeAIProofreadMaxChars(value string) int {
	maxChars, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || maxChars < 0 {
		return 0
	}
	return maxChars
}

func normalizeAIProofreadMaxTokens(value string) int {
	maxTokens, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || maxTokens <= 0 {
		return 16384
	}
	return maxTokens
}

func aiProofreadTokenFallbacks(maxTokens int) []int {
	if maxTokens <= 0 {
		maxTokens = 16384
	}
	candidates := []int{maxTokens}
	for _, fallback := range []int{8192, 4096} {
		if fallback < maxTokens {
			candidates = append(candidates, fallback)
		}
	}
	return candidates
}

func setOption(db *sql.DB, name string, value string) {
	_, err := db.Exec("INSERT INTO go_options (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", name, value)
	if err != nil {
		log.Printf("Error setting option %s: %v", name, err)
	}
}

func isCloudflareRequest(c *gin.Context) bool {
	if strings.TrimSpace(c.GetHeader("CF-Connecting-IP")) != "" {
		return true
	}
	if strings.TrimSpace(c.GetHeader("CF-Ray")) != "" {
		return true
	}
	return false
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
