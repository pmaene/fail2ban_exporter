package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/pmaene/stalecucumber"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	CLIENT_CSPROTO_END   = "<F2B_END_COMMAND>"
	CLIENT_CSPROTO_CLOSE = "<F2B_CLOSE_COMMAND>"
)

var version = ""

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
}

func (c *Client) Dial() error {
	conn, err := net.Dial("unix", c.sock)
	if err != nil {
		return err
	}

	c.conn = conn
	return nil
}
func (c *Client) Send(cmd []string) error {
	b := new(bytes.Buffer)
	if _, err := stalecucumber.NewPickler(b).Pickle(cmd); err != nil {
		return err
	}

	msg := append(
		b.Bytes(),
		[]byte(CLIENT_CSPROTO_END)...,
	)

	if _, err := c.conn.Write(msg); err != nil {
		return err
	}

	return nil
}
func (c Client) Receive() ([]byte, error) {
	var msg []byte

	r := bufio.NewReader(c.conn)
	b := make([]byte, 512)
	for {
		_, err := r.Read(b)
		if err != nil {
			return nil, err
		}

		msg = append(msg, b...)
		if i := bytes.Index(b, []byte(CLIENT_CSPROTO_END)); i != -1 {
			return msg[:i], nil
		}
	}
}
func (c *Client) Close() {
	_, _ = c.conn.Write(
		append(
			[]byte(CLIENT_CSPROTO_CLOSE),
			[]byte(CLIENT_CSPROTO_END)...,
		),
	)

	c.conn.Close()
}

func (c *Client) GetStatus(j string) ([]interface{}, error) {
	if err := c.Dial(); err != nil {
		return nil, err
	}
	defer c.Close()

	cmd := []string{"status"}
	if j != "" {
		cmd = append(cmd, j)
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
	if err := c.Dial(); err != nil {
		return nil, err
	}
	defer c.Close()

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
			return nil, fmt.Errorf("Could not retrieve the filter status for jail \"%s\"", j)
		}

		cf, ok := sf[0].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf("Could not retrieve the currently failed count for jail \"%s\"", j)
		}

		tf, ok := sf[1].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf("Could not retrieve the total failed count for jail \"%s\"", j)
		}

		sa, ok := s[1].([]interface{})[1].([]interface{})
		if !ok {
			return nil, fmt.Errorf("Could not retrieve the filter status for jail \"%s\"", j)
		}

		cb, ok := sa[0].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf("Could not retrieve the currently banned count for jail \"%s\"", j)
		}

		tb, ok := sa[1].([]interface{})[1].(int64)
		if !ok {
			return nil, fmt.Errorf("Could not retrieve the total banned count for jail \"%s\"", j)
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

func NewClient(s string) *Client {
	return &Client{
		sock: s,
	}
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

func NewFail2banExporter(s string) *Fail2banExporter {
	return &Fail2banExporter{
		client: NewClient(s),
	}
}

func getBuildInfo() debug.Module {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		if version != "" {
			return debug.Module{
				Path:    bi.Main.Path,
				Version: version,
				Sum:     bi.Main.Sum,
				Replace: bi.Main.Replace,
			}
		}

		return bi.Main
	}

	return debug.Module{}
}

func init() {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
}

func main() {
	var (
		socketPath = kingpin.Flag(
			"f2b.socket-path",
			"Socket path of the Fail2Ban daemon.",
		).Default("/var/run/fail2ban/fail2ban.sock").String()
		listenAddress = kingpin.Flag(
			"web.listen-address",
			"Address on which to expose metrics and web interface.",
		).Default(":9539").String()
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

	e := NewFail2banExporter(*socketPath)
	defer e.Close()

	prometheus.MustRegister(e)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(
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

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	log.Infoln("Listening on", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
