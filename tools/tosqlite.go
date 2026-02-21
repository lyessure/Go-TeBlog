package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== Typecho 数据库转换工具 (MySQL/PgSQL -> SQLite) ===")

	// 1. 选择数据库类型
	fmt.Print("请选择源数据库类型 (1: MySQL, 2: PostgreSQL) [1]: ")
	dbTypeInput, _ := reader.ReadString('\n')
	dbTypeInput = strings.TrimSpace(dbTypeInput)
	if dbTypeInput == "" {
		dbTypeInput = "1"
	}

	driver := "mysql"
	if dbTypeInput == "2" {
		driver = "postgres"
	}

	// 2. 数据库参数
	fmt.Print("数据库主机 [localhost]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	defaultPort := "3306"
	if driver == "postgres" {
		defaultPort = "5432"
	}
	fmt.Printf("数据库端口 [%s]: ", defaultPort)
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = defaultPort
	}

	fmt.Print("数据库用户名: ")
	user, _ := reader.ReadString('\n')
	user = strings.TrimSpace(user)

	fmt.Print("数据库密码: ")
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)

	fmt.Print("数据库名称: ")
	dbname, _ := reader.ReadString('\n')
	dbname = strings.TrimSpace(dbname)

	fmt.Print("表前缀 [typecho_]: ")
	prefix, _ := reader.ReadString('\n')
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "typecho_"
	}

	// 3. 构造连接字符串
	var dsn string
	if driver == "mysql" {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, pass, host, port, dbname)
	} else {
		sslmode := "disable"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", host, port, user, pass, dbname, sslmode)
	}

	fmt.Printf("\n正在连接到源数据库 (%s)...\n", driver)
	sourceDB, err := sql.Open(driver, dsn)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer sourceDB.Close()

	if err := sourceDB.Ping(); err != nil {
		log.Fatalf("无法访问数据库: %v", err)
	}
	fmt.Println("连接成功！")

	// 4. 创建 SQLite 数据库
	sqliteFile := "blog.sqlite"
	if _, err := os.Stat(sqliteFile); err == nil {
		fmt.Printf("警告: %s 已存在，将被覆盖。确认继续？(y/n) [n]: ", sqliteFile)
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			fmt.Println("已取消。")
			return
		}
		os.Remove(sqliteFile)
	}

	sqliteDB, err := sql.Open("sqlite", sqliteFile)
	if err != nil {
		log.Fatalf("创建 SQLite 失败: %v", err)
	}
	defer sqliteDB.Close()

	// 5. 定义目标表结构
	schemas := map[string]string{
		"comments": `CREATE TABLE "typecho_comments" (
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
		"contents": `CREATE TABLE "typecho_contents" (
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
		"metas": `CREATE TABLE "typecho_metas" (
			"mid" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"name" VARCHAR(150),
			"slug" VARCHAR(150),
			"type" VARCHAR(32) NOT NULL,
			"description" VARCHAR(150),
			"count" INTEGER DEFAULT 0,
			"order" INTEGER DEFAULT 0,
			"parent" INTEGER DEFAULT 0
		)`,
		"options": `CREATE TABLE "typecho_options" (
			"name" VARCHAR(32) NOT NULL,
			"user" INTEGER NOT NULL DEFAULT 0,
			"value" TEXT,
			PRIMARY KEY ("name", "user")
		)`,
		"relationships": `CREATE TABLE "typecho_relationships" (
			"cid" INTEGER NOT NULL,
			"mid" INTEGER NOT NULL,
			PRIMARY KEY ("cid", "mid")
		)`,
		"users": `CREATE TABLE "typecho_users" (
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
		"fields": `CREATE TABLE "typecho_fields" (
			"cid" INTEGER NOT NULL,
			"name" VARCHAR(150) NOT NULL,
			"type" VARCHAR(8) DEFAULT 'str',
			"strValue" TEXT,
			"intValue" INTEGER DEFAULT 0,
			"floatValue" REAL DEFAULT 0,
			PRIMARY KEY ("cid", "name")
		)`,
	}

	// 6. 定义索引
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS "idx_contents_created" ON "typecho_contents" ("created")`,
		`CREATE INDEX IF NOT EXISTS "idx_contents_type_status" ON "typecho_contents" ("type", "status")`,
		`CREATE INDEX IF NOT EXISTS "idx_comments_cid" ON "typecho_comments" ("cid")`,
		`CREATE INDEX IF NOT EXISTS "idx_comments_created" ON "typecho_comments" ("created")`,
		`CREATE INDEX IF NOT EXISTS "idx_comments_status" ON "typecho_comments" ("status")`,
		`CREATE INDEX IF NOT EXISTS "idx_metas_type" ON "typecho_metas" ("type")`,
		`CREATE INDEX IF NOT EXISTS "idx_metas_slug" ON "typecho_metas" ("slug")`,
	}

	tables := []string{"comments", "contents", "metas", "options", "relationships", "users", "fields"}

	type report struct {
		tableName string
		ok        int
		fail      int
		errMsg    string
	}
	var reports []report

	for _, t := range tables {
		sourceTable := prefix + t
		targetTable := "typecho_" + t

		fmt.Printf("正在处理表: %s -> %s... ", sourceTable, targetTable)

		// 创建表
		if _, err := sqliteDB.Exec(schemas[t]); err != nil {
			log.Printf("\nMerr: 创建表 %s 失败: %v", targetTable, err)
			reports = append(reports, report{targetTable, 0, 0, err.Error()})
			continue
		}

		// 获取 SQLite (目标) 表的列及其真实名字
		targetColsMap := make(map[string]string)
		res, err := sqliteDB.Query(fmt.Sprintf("SELECT * FROM %s LIMIT 0", targetTable))
		if err == nil {
			tCols, _ := res.Columns()
			for _, c := range tCols {
				targetColsMap[strings.ToLower(c)] = c
			}
			res.Close()
		}

		// 读取源数据
		rows, err := sourceDB.Query(fmt.Sprintf("SELECT * FROM %s", sourceTable))
		if err != nil {
			fmt.Printf("跳过 (源表不存在)\n")
			continue
		}

		sourceCols, _ := rows.Columns()

		// 找出交集列：映射逻辑 -> 目标列名
		var targetColNames []string
		var sourceColIndices []int
		for i, c := range sourceCols {
			if realName, ok := targetColsMap[strings.ToLower(c)]; ok {
				targetColNames = append(targetColNames, realName)
				sourceColIndices = append(sourceColIndices, i)
			}
		}

		if len(targetColNames) == 0 {
			fmt.Printf("跳过 (无匹配列)\n")
			rows.Close()
			continue
		}

		okCount, failCount := 0, 0
		var firstErr, lastErr string
		recordErr := func(err error) {
			if err == nil {
				return
			}
			failCount++
			lastErr = err.Error()
			if firstErr == "" {
				firstErr = lastErr
			}
		}

		tx, err := sqliteDB.Begin()
		if err != nil {
			log.Printf("\nMerr: 开启事务失败: %v", err)
			rows.Close()
			reports = append(reports, report{targetTable, 0, 0, err.Error()})
			continue
		}

		for rows.Next() {
			values := make([]interface{}, len(sourceCols))
			valuePtrs := make([]interface{}, len(sourceCols))
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				recordErr(err)
				continue
			}

			// 准备数据
			insertValues := make([]interface{}, len(targetColNames))
			for i, srcIdx := range sourceColIndices {
				val := values[srcIdx]
				if b, ok := val.([]byte); ok {
					insertValues[i] = string(b)
				} else {
					insertValues[i] = val
				}
			}

			// 构造 SQL
			placeholder := make([]string, len(targetColNames))
			for i := range placeholder {
				placeholder[i] = "?"
			}
			insertQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
				targetTable,
				strings.Join(quoteColumns(targetColNames), ", "),
				strings.Join(placeholder, ", "))

			_, err = tx.Exec(insertQuery, insertValues...)
			if err != nil {
				recordErr(err)
			} else {
				okCount++
			}
		}

		// 检查扫描过程是否有错
		if err := rows.Err(); err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("读取中断: %v", err)
			}
		}
		rows.Close()

		if err := tx.Commit(); err != nil {
			log.Printf("\nMerr: 提交事务失败: %v", err)
			if firstErr == "" {
				firstErr = err.Error()
			}
		}

		fmt.Printf("成功: %d, 失败: %d\n", okCount, failCount)
		reports = append(reports, report{targetTable, okCount, failCount, firstErr})
	}

	// 开启 WAL 模式以提高并发性能
	sqliteDB.Exec("PRAGMA journal_mode=WAL;")

	// 执行索引创建
	fmt.Println("正在创建数据库索引...")
	for _, idx := range indexes {
		if _, err := sqliteDB.Exec(idx); err != nil {
			log.Printf("创建索引失败: %v", err)
		}
	}

	fmt.Println("\n================ 迁移报表汇总 ================")
	fmt.Printf("%-25s %-10s %-10s %-s\n", "表名", "成功", "失败", "第一条错误/状态")
	fmt.Println(strings.Repeat("-", 75))
	hasFail := false
	for _, r := range reports {
		status := "OK"
		if r.fail > 0 || r.errMsg != "" {
			status = r.errMsg
			hasFail = true
		}
		fmt.Printf("%-25s %-10d %-10d %-s\n", r.tableName, r.ok, r.fail, status)
	}
	fmt.Println("==============================================")

	if hasFail {
		fmt.Println("\n[警告] 检测到部分数据未成功迁移，请检查源库数据一致性。")
	}

	fmt.Println("\n转换程序执行完毕！")
	fmt.Println("--------------------------------------------------")
	fmt.Printf("生成的 SQLite 文件: %s\n", sqliteFile)
	fmt.Println("部署建议:")
	fmt.Printf("  mv %s ../%s\n", sqliteFile, sqliteFile)
	fmt.Println("然后重启您的博客服务。")
	fmt.Println("--------------------------------------------------")
}

func quoteColumns(cols []string) []string {
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = fmt.Sprintf("\"%s\"", c)
	}
	return quoted
}
