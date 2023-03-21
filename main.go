package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"strings"

	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	logger        *logrus.Logger
	logLevel      string
	netInfoUrl    string
	statusUrl     string
	listenAddress string
	sleepTimeout  int
)

const (
	namespace = "p2p"
	subsystem = "cosmos"
)

// Full struct for status.json
type ProtocolVersion struct {
	P2P   string `json:"p2p"`
	Block string `json:"block"`
	App   string `json:"app"`
}

type Other struct {
	TxIndex    string `json:"tx_index"`
	RPCAddress string `json:"rpc_address"`
}

type PubKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type NodeInfo struct {
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
	ID              string          `json:"id"`
	ListenAddr      string          `json:"listen_addr"`
	Network         string          `json:"network"`
	Version         string          `json:"version"`
	Channels        string          `json:"channels"`
	Moniker         string          `json:"moniker"`
	Other           Other           `json:"other"`
}

type SyncInfo struct {
	LatestBlockHash     string `json:"latest_block_hash"`
	LatestAppHash       string `json:"latest_app_hash"`
	LatestBlockHeight   string `json:"latest_block_height"`
	LatestBlockTime     string `json:"latest_block_time"`
	EarliestBlockHash   string `json:"earliest_block_hash"`
	EarliestAppHash     string `json:"earliest_app_hash"`
	EarliestBlockHeight string `json:"earliest_block_height"`
	EarliestBlockTime   string `json:"earliest_block_time"`
	CatchingUp          bool   `json:"catching_up"`
}

type ValidatorInfo struct {
	Address     string `json:"address"`
	PubKey      PubKey `json:"pub_key"`
	VotingPower string `json:"voting_power"`
}

type Result struct {
	NodeInfo      NodeInfo      `json:"node_info"`
	SyncInfo      SyncInfo      `json:"sync_info"`
	ValidatorInfo ValidatorInfo `json:"validator_info"`
}

type StatusResponseData struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      int64  `json:"id"`
	Result  Result `json:"result"`
}

// Short struct for net_info.json
type NetInfoResult struct {
	Listening bool     `json:"-"`
	Listeners []string `json:"-"`
	NPeers    string   `json:"n_peers"`
}

type NetInfoData struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      int64         `json:"-"`
	Result  NetInfoResult `json:"result"`
}

func fetchStatus(url string) (map[string]interface{}, error) {

	client := http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Prometheus-Exporter")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	data := StatusResponseData{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	dataMap := make(map[string]interface{})

	LastBlockNumber, err := strconv.ParseFloat(data.Result.SyncInfo.LatestBlockHeight, 64)
	if err != nil {
		log.Fatalf("Can not convert lastBlockNumber to float64. Err: %s", err)
	}
	dataMap["lastBlockNumber"] = LastBlockNumber

	latestBlockTimeString := data.Result.SyncInfo.LatestBlockTime
	tLatest, err := time.Parse(time.RFC3339Nano, latestBlockTimeString)
	tNow := time.Now()
	tDrift := tNow.Sub(tLatest).Seconds()
	dataMap["timeDrift"] = tDrift

	return dataMap, nil

}

func fetchNetInfo(url string) (map[string]interface{}, error) {

	client := http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Prometheus-Exporter")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	data := NetInfoData{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	dataMap := make(map[string]interface{})

	peerCount, err := strconv.ParseFloat(data.Result.NPeers, 64)
	if err != nil {
		log.Fatalf("Can not convert peerCount to float64. Err: %s", err)
	}
	dataMap["peerCount"] = peerCount

	return dataMap, nil

}

func init() {

	flag.StringVar(&listenAddress, "listen-address", ":8080", "Address to listen on for web interface and telemetry")
	flag.StringVar(&netInfoUrl, "net-info-url", "http://localhost:26657/net_info", "The URL to fetch the Net Info  metrics from")
	flag.StringVar(&statusUrl, "status-url", "http://localhost:26657/status", "The URL to fetch the Status metrics from")
	flag.StringVar(&logLevel, "log-level", "info", "The Log Level")
	flag.IntVar(&sleepTimeout, "sleep-timeout", 60, "The time in seconds for get metrics")
	flag.Parse()

	logger = logrus.New()
	logLevel := logLevel
	switch strings.ToLower(logLevel) {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warning":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logger.SetLevel(logrus.FatalLevel)
	case "panic":
		logger.SetLevel(logrus.PanicLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.JSONFormatter{})
}

func main() {

	logger.Info("Started")

	lastBlockNumber := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "last_block_number",
		Help:      "The number of last block",
	})
	timeDrift := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "time_drift",
		Help:      "The time drift of last block",
	})
	peerCounter := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "peer_count",
		Help:      "The count of peers",
	})

	prometheus.MustRegister(lastBlockNumber)
	prometheus.MustRegister(timeDrift)
	prometheus.MustRegister(peerCounter)

	go func() {
		for {

			statusData, err := fetchStatus(string(statusUrl))
			if err != nil {
				logger.WithError(err).Error("Can not get data from %s", statusUrl)
				time.Sleep(3 * time.Second)
				continue
			}
			assertLastBlockNumber := statusData["lastBlockNumber"].(float64)
			lastBlockNumber.Set(assertLastBlockNumber)
			assertTimeDrift := statusData["timeDrift"].(float64)
			timeDrift.Set(assertTimeDrift)

			netInfoData, err := fetchNetInfo(netInfoUrl)
			if err != nil {
				logger.WithError(err).Error("Can not get data from %s", netInfoUrl)
				time.Sleep(3 * time.Second)
				continue
			}
			assertPeerCount := netInfoData["peerCount"].(float64)
			peerCounter.Set(assertPeerCount)

			time.Sleep(time.Duration(sleepTimeout) * time.Second)
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
