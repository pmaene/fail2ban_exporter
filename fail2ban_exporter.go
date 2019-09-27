package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"golang.org/x/sync/semaphore"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/cenkalti/backoff"
	"github.com/pmaene/stalecucumber"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

const (
	CLIENT_CSPROTO_END   = "<F2B_END_COMMAND>"
	CLIENT_CSPROTO_CLOSE = "<F2B_CLOSE_COMMAND>"
)

var (
	fail2banUpDesc = prometheus.NewDesc(
		prometheus.BuildFQName("fail2ban", "", "up"),
		"Whether collecting fail2ban's metrics was successful.",
		nil,
		nil,
	)
	fail2banFailedCurrentDesc = prometheus.NewDesc(
		prometheus.BuildFQName("fail2ban", "", "failed_current"),
		"Number of currently failed connections by jail.",
		[]string{"jail"},
		nil,
	)
	fail2banFailedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName("fail2ban", "", "failed_total"),
		"Number of total failed connections by jail.",
		[]string{"jail"},
		nil,
	)
	fail2banBannedCurrentDesc = prometheus.NewDesc(
		prometheus.BuildFQName("fail2ban", "", "banned_current"),
		"Number of currently banned connections by jail.",
		[]string{"jail"},
		nil,
	)
	fail2banBannedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName("fail2ban", "", "banned_total"),
		"Number of total banned connections by jail.",
		[]string{"jail"},
		nil,
	)
)

type Jail struct {
	Name string

	CurrentlyFailed int64
	TotalFailed     int64
	CurrentlyBanned int64
	TotalBanned     int64
}

type Client struct {
	conn net.Conn
	sock string
	lock *semaphore.Weighted
}

func (c *Client) IsConnected() bool {
	if c.conn == nil {
		return false
	}

	if _, err := c.conn.Write(make([]byte, 0)); err != nil {
		return false
	}

	return true
}

func (c *Client) Dial() error {
	go func() {
		if !c.lock.TryAcquire(1) {
			return
		}

		dial := func() error {
			conn, err := net.Dial("unix", c.sock)
			if err != nil {
				return err
			}

			c.conn = conn
			return nil
		}

		err := backoff.Retry(dial, backoff.NewExponentialBackOff())
		if err != nil {
			log.Fatal(err)
		}

		c.lock.Release(1)
	}()

	return nil
}
func (c *Client) Send(cmd []string) error {
	if !c.IsConnected() {
		return c.Dial()
	}

	b := new(bytes.Buffer)
	if _, err := stalecucumber.NewPickler(b).Pickle(cmd); err != nil {
		return err
	}

	msg := append(
		b.Bytes(),
		[]byte(CLIENT_CSPROTO_END)...,
	)

	if _, err := c.conn.Write(msg); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
			return c.Dial()
		}

		return err
	}

	return nil
}
func (c Client) Receive() ([]byte, error) {
	if !c.IsConnected() {
		return nil, c.Dial()
	}

	msg := []byte{}

	r := bufio.NewReader(c.conn)
	b := make([]byte, 512)
	for {
		_, err := r.Read(b)
		if err != nil {
			if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
				return nil, c.Dial()
			}

			return nil, err
		}

		msg = append(msg, b...)
		if i := bytes.Index(b, []byte(CLIENT_CSPROTO_END)); i != -1 {
			return msg[:i], nil
		}
	}

	return nil, fmt.Errorf("")
}
func (c *Client) Close() {
	if !c.IsConnected() {
		return
	}

	c.conn.Write(
		append(
			[]byte(CLIENT_CSPROTO_CLOSE),
			[]byte(CLIENT_CSPROTO_END)...,
		),
	)

	c.conn.Close()
}

func (c *Client) GetStatus(jail string) ([]interface{}, error) {
	cmd := []string{"status"}
	if jail != "" {
		cmd = append(cmd, jail)
	}

	if err := c.Send(cmd); err != nil {
		return nil, err
	}

	msg, err := c.Receive()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(msg)
	d, err := stalecucumber.ListOrTuple(stalecucumber.Unpickle(r))
	if err != nil {
		return nil, err
	}

	rc, ok := d[0].(int64)
	if !ok {
		return nil, errors.New("Could not retrieve the jail status")
	}

	if rc > 0 {
		return nil, errors.New("Could not retrieve the jail status")
	}

	s, ok := d[1].([]interface{})
	if !ok {
		return nil, errors.New("Could not retrieve the jail status")
	}

	return s, nil
}
func (c *Client) GetJails() ([]*Jail, error) {
	s, err := c.GetStatus("")
	if err != nil {
		return nil, err
	}

	ss, ok := s[1].([]interface{})
	if !ok {
		return nil, errors.New("Could not retrieve the jail list")
	}

	jl, ok := ss[1].(string)
	if !ok {
		return nil, errors.New("Could not retrieve the jail list")
	}

	js := []*Jail{}
	for _, j := range strings.Split(jl, ",") {
		s, err = c.GetStatus(j)
		if err != nil {
			return nil, err
		}

		sf, ok := s[0].([]interface{})[1].([]interface{})
		if !ok {
			return nil, fmt.Errorf(
				"Could not retrieve the filter status for jail \"%s\"",
				j,
			)
		}

		cf, ok := sf[0].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf(
				"Could not retrieve the currently failed count for jail \"%s\"",
				j,
			)
		}

		tf, ok := sf[1].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf(
				"Could not retrieve the total failed count for jail \"%s\"",
				j,
			)
		}

		sa, ok := s[1].([]interface{})[1].([]interface{})
		if !ok {
			return nil, fmt.Errorf(
				"Could not retrieve the filter status for jail \"%s\"",
				j,
			)
		}

		cb, ok := sa[0].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf(
				"Could not retrieve the currently banned count for jail \"%s\"",
				j,
			)
		}

		tb, ok := sa[1].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf(
				"Could not retrieve the total banned count for jail \"%s\"",
				j,
			)
		}

		js = append(
			js,
			&Jail{
				Name: j,

				CurrentlyFailed: cf,
				TotalFailed:     tf,
				CurrentlyBanned: cb,
				TotalBanned:     tb,
			},
		)
	}

	return js, nil
}

func NewClient(sock string) (*Client, error) {
	return &Client{sock: sock, lock: semaphore.NewWeighted(1)}, nil
}

type Fail2banExporter struct {
	client *Client
}

func (e *Fail2banExporter) Close() {
	e.client.Close()
}

func (e *Fail2banExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- fail2banUpDesc
	ch <- fail2banFailedCurrentDesc
	ch <- fail2banFailedTotalDesc
	ch <- fail2banBannedCurrentDesc
	ch <- fail2banBannedTotalDesc
}
func (e *Fail2banExporter) Collect(ch chan<- prometheus.Metric) {
	js, err := e.client.GetJails()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			fail2banUpDesc,
			prometheus.GaugeValue,
			0.0,
		)

		return
	}

	for _, j := range js {
		ch <- prometheus.MustNewConstMetric(
			fail2banFailedCurrentDesc,
			prometheus.GaugeValue,
			float64(j.CurrentlyFailed),
			j.Name,
		)

		ch <- prometheus.MustNewConstMetric(
			fail2banFailedTotalDesc,
			prometheus.GaugeValue,
			float64(j.TotalFailed),
			j.Name,
		)

		ch <- prometheus.MustNewConstMetric(
			fail2banBannedCurrentDesc,
			prometheus.GaugeValue,
			float64(j.CurrentlyBanned),
			j.Name,
		)

		ch <- prometheus.MustNewConstMetric(
			fail2banBannedTotalDesc,
			prometheus.GaugeValue,
			float64(j.TotalBanned),
			j.Name,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		fail2banUpDesc,
		prometheus.GaugeValue,
		1.0,
	)
}

func NewFail2banExporter() (*Fail2banExporter, error) {
	c, err := NewClient("/var/run/fail2ban/fail2ban.sock")
	if err != nil {
		return nil, err
	}

	c.Dial()

	return &Fail2banExporter{c}, nil
}

func getBuildInfo() debug.Module {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		return bi.Main
	}

	return debug.Module{Version: "unknown"}
}

func main() {
	var (
		listenAddress = kingpin.Flag(
			"web.listen-address",
			"Address on which to expose metrics and web interface.",
		).Default(":9121").String()
		metricsPath = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default("/metrics").String()
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(
		fmt.Sprintf(
			"%s %s compiled with %v on %v/%v",
			kingpin.CommandLine.Name,
			getBuildInfo().Version,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH,
		),
	)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infoln("Starting", kingpin.CommandLine.Name, getBuildInfo().Version)

	e, err := NewFail2banExporter()
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	prometheus.MustRegister(e)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(
			[]byte(
				`<html>
				<head><title>Fail2ban Exporter</title></head>
				<body>
				<h1>Fail2ban Exporter</h1>
				<p><a href='` + *metricsPath + `'>Metrics</a></p>
				</body>
				</html>`,
			),
		)
	})

	log.Infoln("Listening on", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatal(err)
	}
}
