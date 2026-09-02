// tenantwatch is the TenantWatch product binary: read-only Microsoft 365 and
// Google Workspace security-posture auditing on Sentinel Core.
//
//	tenantwatch                       # dashboard on 127.0.0.1:8430
//	tenantwatch -creds tenants.json   # credentials for the tenants to read
//
// Add a tenant as "m365:contoso.onmicrosoft.com" or "gws:contoso.co.id"; give
// TenantWatch read-only credentials for it (see INSTALL), and it reports the
// MFA gaps, risky app consents, admin sprawl, sharing exposure, and email-auth
// weaknesses that a workspace accumulates — as prioritised, self-resolving
// findings.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/nizartuanku/tenantwatch/notify"
	"github.com/nizartuanku/tenantwatch/sched"
	"github.com/nizartuanku/tenantwatch/store"
	"github.com/nizartuanku/tenantwatch/tenant"
	"github.com/nizartuanku/tenantwatch/tenantwatch"
	"github.com/nizartuanku/tenantwatch/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

func main() {
	listen := flag.String("listen", "127.0.0.1:8430", "dashboard listen address")
	dbPath := flag.String("db", "tenantwatch.db", "SQLite database path")
	licFile := flag.String("license", "tenantwatch-license.key", "license key file")
	credsPath := flag.String("creds", "tenants.json", "tenant credentials file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
	syslogAddr := flag.String("syslog", "", "syslog collector host:port (point at Loglight to correlate across products)")
	syslogNet := flag.String("syslog-network", "udp", "syslog transport: udp or tcp")
	flag.Parse()

	creds, err := tenantwatch.LoadCreds(*credsPath)
	if err != nil {
		fatal(err.Error())
	}
	src := tenantwatch.New(creds)

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	module := tenant.New(src)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}
	modID := module.Describe().ID

	if saved, err := st.ListSavedTargets(modID); err == nil {
		for _, raw := range saved {
			if _, err := scheduler.AddTarget(modID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "tenantwatch: skipping saved tenant %q: %v\n", raw, err)
			}
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)
	server.Targets = st
	server.TierLimits = tenantwatch.TierLimits

	var channels []notify.Channel
	if *webhook != "" {
		channels = append(channels, &notify.WebhookChannel{URL: *webhook})
	}
	if *syslogAddr != "" {
		channels = append(channels, &notify.SyslogChannel{Addr: *syslogAddr, Network: *syslogNet})
	}
	if len(channels) > 0 {
		disp := notify.NewDispatcher(notify.Config{}, channels...)
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("TenantWatch %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "tenantwatch: "+msg)
	os.Exit(1)
}
