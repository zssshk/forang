// doctor.go 是 `artex doctor` 部署预检（v0.6.3，FORANG 自研，只读不改任何东西）。
//
// 用法：artex doctor [--data <数据目录>] [--manifest <清单路径>]
// 检查项：
//  1. PostgreSQL：DSN 可解析、能连通、SELECT 1 通过、llm_profiles 可读；
//  2. 数据目录：存在且可写；
//  3. jwt.key：存在（config.BaseDir() 或数据目录）；凭据库加密靠它，缺了
//     凭据工具会直接报不可用；
//  4. v0.6.3 内网/蜜罐表结构：credentials / tunnels / pending_scope 与
//     assets.honeypot_score 列（缺失只警告——首次启动时 schema 还没跑）；
//  5. v0.6.4 证据分级/质量闭环表结构：finding_reviews / finding_dedup_events /
//     finding_regressions 表与 findings.evidence_level 等列（同上，只警告）；
//  5. 外部工具钉版清单（packaging/tools-manifest.json）：存在且哈希匹配为 OK，
//     未钉版/找不到只警告，哈希不匹配才 FAIL。
//
// 任一 FAIL → exit 1；只有 WARN → exit 0。
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/toolscheck"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver ("pgx")
)

type doctorReport struct {
	fails int
	warns int
}

func (r *doctorReport) ok(name, detail string) {
	fmt.Printf("[OK]   %s %s\n", name, detail)
}

func (r *doctorReport) warn(name, detail string) {
	r.warns++
	fmt.Printf("[WARN] %s %s\n", name, detail)
}

func (r *doctorReport) fail(name, detail string) {
	r.fails++
	fmt.Printf("[FAIL] %s %s\n", name, detail)
}

// runDoctor 是 `artex doctor` 的入口（只读预检，不写库不改文件）。
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	dataDir := fs.String("data", filepath.Join(config.BaseDir(), "data"), "data directory")
	manifestPath := fs.String("manifest", "", "tools manifest path (default: data/tools-manifest.json, exe dir, ./packaging/tools-manifest.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rep := &doctorReport{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("artex doctor · version %s\n", version)

	// 1. PostgreSQL
	dsn, source, err := db.DSN()
	if err != nil {
		rep.fail("postgres", "DSN 无法解析: "+err.Error())
	} else {
		sqldb, err := sql.Open("pgx", dsn)
		if err != nil {
			rep.fail("postgres", "sql.Open 失败: "+err.Error())
		} else {
			defer sqldb.Close()
			if err := sqldb.PingContext(ctx); err != nil {
				rep.fail("postgres", fmt.Sprintf("连接失败（来源 %s）: %v", source, err))
			} else {
				rep.ok("postgres", fmt.Sprintf("连通（来源 %s）", source))
				var one int
				if err := sqldb.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
					rep.fail("postgres", "SELECT 1 失败: "+err.Error())
				}
				var n int
				if err := sqldb.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_profiles").Scan(&n); err != nil {
					rep.warn("llm_profiles", "表不可读: "+err.Error())
				} else {
					rep.ok("llm_profiles", fmt.Sprintf("%d 条配置", n))
				}
				// v0.6.3 内网/蜜罐表结构（首次启动前 schema 未跑时只警告）。
				for _, q := range []struct{ name, sql string }{
					{"credentials 表", "SELECT 1 FROM information_schema.tables WHERE table_name='credentials'"},
					{"tunnels 表", "SELECT 1 FROM information_schema.tables WHERE table_name='tunnels'"},
					{"pending_scope 表", "SELECT 1 FROM information_schema.tables WHERE table_name='pending_scope'"},
					{"assets.honeypot_score 列", "SELECT 1 FROM information_schema.columns WHERE table_name='assets' AND column_name='honeypot_score'"},
					// v0.6.4 证据分级/质量闭环表结构。
					{"finding_reviews 表", "SELECT 1 FROM information_schema.tables WHERE table_name='finding_reviews'"},
					{"finding_dedup_events 表", "SELECT 1 FROM information_schema.tables WHERE table_name='finding_dedup_events'"},
					{"finding_regressions 表", "SELECT 1 FROM information_schema.tables WHERE table_name='finding_regressions'"},
					{"findings.evidence_level 列", "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='evidence_level'"},
					{"findings.confidence 列", "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='confidence'"},
					{"findings.report_excluded 列", "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='report_excluded'"},
				} {
					var one int
					if err := sqldb.QueryRowContext(ctx, q.sql).Scan(&one); err != nil {
						rep.warn(q.name, "不存在（首次启动前属正常，启动后 schema 会补）")
					} else {
						rep.ok(q.name, "存在")
					}
				}
			}
		}
	}

	// 2. 数据目录可写
	if fi, err := os.Stat(*dataDir); err != nil || !fi.IsDir() {
		rep.fail("data 目录", *dataDir+" 不存在或不是目录")
	} else if f, err := os.CreateTemp(*dataDir, ".doctor-write-*"); err != nil {
		rep.fail("data 目录", *dataDir+" 不可写: "+err.Error())
	} else {
		_ = f.Close()
		_ = os.Remove(f.Name())
		rep.ok("data 目录", *dataDir+" 可写")
	}

	// 3. jwt.key（凭据库加密主钥）
	keyFound := ""
	for _, p := range []string{
		filepath.Join(config.BaseDir(), "jwt.key"),
		filepath.Join(*dataDir, "jwt.key"),
	} {
		if _, err := os.Stat(p); err == nil {
			keyFound = p
			break
		}
	}
	if keyFound == "" {
		rep.fail("jwt.key", "未找到（config.BaseDir() 与数据目录均无）；凭据库将不可用")
	} else {
		rep.ok("jwt.key", keyFound)
	}

	// 4. 外部工具钉版清单
	manifest := *manifestPath
	if manifest == "" {
		exe, _ := os.Executable()
		candidates := []string{
			filepath.Join(*dataDir, "tools-manifest.json"),
			filepath.Join(filepath.Dir(exe), "tools-manifest.json"),
			"packaging/tools-manifest.json",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				manifest = c
				break
			}
		}
	}
	if manifest == "" {
		rep.warn("工具清单", "未找到 tools-manifest.json（data 目录/可执行文件目录/packaging 均无），跳过工具校验")
	} else {
		m, err := toolscheck.Load(manifest)
		if err != nil {
			rep.fail("工具清单", err.Error())
		} else {
			rep.ok("工具清单", fmt.Sprintf("%s（%d 条）", manifest, len(m.Tools)))
			for _, res := range toolscheck.Check(m, *dataDir) {
				detail := res.Tool.Name + "：" + res.Message
				if res.FoundAt != "" {
					detail += " @ " + res.FoundAt
				}
				switch res.Status {
				case toolscheck.StatusOK:
					rep.ok("工具", detail)
				case toolscheck.StatusMismatch:
					rep.fail("工具", detail)
				default: // unpinned / missing：只警告
					rep.warn("工具", detail)
				}
			}
		}
	}

	fmt.Println(strings.Repeat("-", 60))
	if rep.fails > 0 {
		fmt.Printf("doctor: %d FAIL, %d WARN — 部署前须修 FAIL 项\n", rep.fails, rep.warns)
		return 1
	}
	fmt.Printf("doctor: 通过（%d WARN）\n", rep.warns)
	return 0
}
