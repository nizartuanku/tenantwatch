// Demo serves the TenantWatch dashboard against a canned tenant, so the
// product can be seen working without wiring real Microsoft 365 or Google
// Workspace credentials.
//
// This is what the demo GIF in the README is recorded from: a real binary, the
// real check engine and the real dashboard — only the cloud API is replaced.
// Nothing here is presented as a real customer's data; the tenant is
// contoso.example, the reserved documentation domain.
//
//	go run ./cmd/demo            # dashboard on 127.0.0.1:8430
//	go run ./cmd/demo -listen :9000
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nizartuanku/tenantwatch/sched"
	"github.com/nizartuanku/tenantwatch/store"
	"github.com/nizartuanku/tenantwatch/tenant"
	"github.com/nizartuanku/tenantwatch/tenantwatch"
	"github.com/nizartuanku/tenantwatch/web"
)

// demoSource returns the same canned snapshot every scan, so the dashboard is
// deterministic and the recording is reproducible.
type demoSource struct{ now time.Time }

func (d demoSource) Snapshot(context.Context, string, string) (tenant.TenantState, error) {
	return demoState(d.now), nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8430", "dashboard listen address")
	// hold delays adding the tenant, so a recording can capture the real
	// empty-then-filling transition from one running instance instead of
	// faking it with two screenshots.
	hold := flag.Duration("hold", 0, "wait this long before adding the demo tenant")
	flag.Parse()

	now := time.Now().UTC()
	module := tenant.New(demoSource{now: now})

	ms := store.NewMemStore()
	engine := store.NewEngine(ms)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		panic(err)
	}
	addTenant := func() {
		if _, err := scheduler.AddTarget(tenant.ModuleID, "m365:contoso.example"); err != nil {
			panic(err)
		}
	}

	server := web.NewServer(module.Describe(), ms, scheduler, nil, "")
	server.Targets = nil
	// The demo must show the edition a visitor would actually download. Without
	// this it falls back to the engine's generic defaults and the dashboard
	// advertises ten free tenants instead of one.
	server.TierLimits = tenantwatch.TierLimits

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		panic(err)
	}
	if *hold > 0 {
		go func() { time.Sleep(*hold); addTenant() }()
	} else {
		addTenant()
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("TenantWatch demo — canned tenant contoso.example\n")
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}

// demoState is a small business that looks like most small businesses do:
// mostly fine, with two or three things quietly wrong — and a sign-in log that
// turns one of them from a policy note into an incident.
func demoState(now time.Time) tenant.TenantState {
	ago := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }

	users := []tenant.User{
		{ID: "1", Email: "andi@contoso.example", DisplayName: "Andi", Enabled: true,
			IsAdmin: true, AdminRoles: []string{"Global Administrator"}, MFAEnabled: false, LastActive: ago(2)},
		{ID: "2", Email: "sari@contoso.example", DisplayName: "Sari", Enabled: true, MFAEnabled: true, LastActive: ago(5)},
		{ID: "3", Email: "budi@contoso.example", DisplayName: "Budi", Enabled: true, MFAEnabled: true, LastActive: ago(30)},
		{ID: "4", Email: "sales@contoso.example", DisplayName: "Sales (shared)", Enabled: true, MFAEnabled: false, LastActive: ago(1)},
		{ID: "5", Email: "intern@contoso.example", DisplayName: "Intern 2024", Enabled: true, MFAEnabled: false,
			LastActive: now.AddDate(0, -7, 0)},
	}

	var signIns []tenant.SignIn

	// A mail client polling over IMAP, successfully — the door that cannot
	// carry MFA, in daily use.
	for i := 0; i < 9; i++ {
		signIns = append(signIns, tenant.SignIn{
			UserEmail: "sales@contoso.example", At: ago(30 - i*3), Success: true,
			Country: "VN", IP: "203.0.113.9", ClientApp: "IMAP4", LegacyAuth: true,
		})
	}

	// The admin signing in with a password alone.
	signIns = append(signIns,
		tenant.SignIn{UserEmail: "andi@contoso.example", At: ago(26), Success: true,
			Country: "ID", IP: "198.51.100.4", ClientApp: "Browser", SingleFactor: true},
		tenant.SignIn{UserEmail: "andi@contoso.example", At: ago(2), Success: true,
			Country: "ID", IP: "198.51.100.4", ClientApp: "Browser", SingleFactor: true},
	)

	// Two countries, 38 minutes apart.
	signIns = append(signIns,
		tenant.SignIn{UserEmail: "sari@contoso.example", At: ago(9), Success: true,
			Country: "ID", IP: "198.51.100.77", ClientApp: "Browser"},
		tenant.SignIn{UserEmail: "sari@contoso.example", At: ago(9).Add(38 * time.Minute), Success: true,
			Country: "SG", IP: "203.0.113.212", ClientApp: "Browser"},
	)

	// A spray that landed: many accounts tried from one address, then one fell.
	for i := 0; i < 14; i++ {
		signIns = append(signIns, tenant.SignIn{
			UserEmail: fmt.Sprintf("user%d@contoso.example", i%7),
			At:        ago(48).Add(time.Duration(i*3) * time.Minute),
			Success:   false, IP: "192.0.2.66", ClientApp: "Browser", FailureCode: "50126",
		})
	}
	signIns = append(signIns, tenant.SignIn{
		UserEmail: "budi@contoso.example", At: ago(47), Success: true,
		Country: "RU", IP: "192.0.2.66", ClientApp: "Browser",
	})

	return tenant.TenantState{
		Provider: tenant.ProviderM365,
		Domain:   "contoso.example",
		TakenAt:  now,
		Users:    users,
		Grants: []tenant.OAuthGrant{{
			AppID: "a1", AppName: "PDF Converter Free", ConsentType: "AllPrincipals",
			Scopes: []string{"Mail.Read", "Files.ReadWrite.All"},
		}},
		Domains: []tenant.DomainAuth{{
			Domain: "contoso.example", SPF: true, DKIM: true, DMARCPolicy: "none",
		}},
		Sharing:           tenant.SharingConfig{AnyoneLinks: true, ExternalSharing: true, Level: "ExternalUserAndGuestSharing"},
		LegacyAuthEnabled: true,
		ConditionalAccess: false,
		SignIns:           signIns,
		Assessed: map[string]bool{
			tenant.AreaMFA: true, tenant.AreaLegacyAuth: true, tenant.AreaOAuth: true,
			tenant.AreaAdminRoles: true, tenant.AreaSharing: true, tenant.AreaEmailAuth: true,
			tenant.AreaConditional: true, tenant.AreaInactiveUser: true, tenant.AreaSignIn: true,
		},
		Notes: []string{
			"external mailbox auto-forwarding needs Exchange mailbox read — assess manually",
		},
	}
}
