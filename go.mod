module github.com/pmaene/fail2ban_exporter

go 1.13

require (
	github.com/kisielk/og-rek v1.1.0
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/common v0.24.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/kisielk/og-rek => github.com/pmaene/og-rek v1.1.1-0.20201110172418-8cecc80af080
