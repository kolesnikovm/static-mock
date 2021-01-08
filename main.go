package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"

	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"
)

type defaultResponse struct {
	MockName string               `json:"mockName"`
	Handlers []handlerDescription `json:"handlers"`
}

type handlerDescription struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
}

type Config struct {
	Handler      string       `yaml:"handler"`
	ResponseFile string       `yaml:"responseFile"`
	ResponseTime ResponseTime `yaml:"responseTime,omitempty"`
	ErrorRate    float64      `yaml:"errorRate,omitempty"`
}

type ResponseTime struct {
	Mean      float64 `yaml:"mean,omitempty"`
	Deviation float64 `yaml:"deviation,omitempty"`
}

func getConfig() {
	file, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	err = yaml.Unmarshal(file, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	for _, c := range config {
		if c.ResponseTime.Deviation < 0 || c.ResponseTime.Mean < 0 {
			log.Fatalf("Deviation and Mean must be in [0, +inf), got: Deviation %.0f, Mean %.0f", c.ResponseTime.Deviation, c.ResponseTime.Mean)
		}

		if c.ErrorRate < 0 || c.ErrorRate > 1 {
			log.Fatalf("ErrorRate must be in [0,1], got: %.2f", c.ErrorRate)
		}
	}
}

func wait(deviation, mean float64) {
	timeout := rand.NormFloat64()*deviation + mean
	time.Sleep(time.Duration(timeout) * time.Millisecond)
}

func getIPAddress() (address string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Errorf("Cant get interface addresses: %s", err)
		return address
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return address
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	var handlers []handlerDescription

	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()

		methods := make([]string, 0)
		m, _ := route.GetMethods()
		methods = append(methods, m...)

		handler := handlerDescription{
			Path:    path,
			Methods: methods,
		}
		handlers = append(handlers, handler)

		return nil
	})

	response, _ := json.Marshal(&defaultResponse{
		MockName: *mockName,
		Handlers: handlers,
	})

	w.WriteHeader(http.StatusNotFound)
	w.Write(response)
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot)
}

func middleware(f http.HandlerFunc, c Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				log.Debug("Recovered from error")
			}
			requestsDuration.WithLabelValues(*mockName, ipAddress, *port, r.URL.Path).Observe(float64(time.Since(start).Milliseconds()))
		}()

		log.Infof("%s request to %s", r.Method, r.URL)

		rate := rand.Float64()
		if rate < c.ErrorRate {
			errorHandler(w, r)
		} else {
			wait(c.ResponseTime.Deviation, c.ResponseTime.Mean)
			f(w, r)
		}
	}
}

func fileHandler(file string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, file)
	}
}

var (
	mockName       = flag.String("name", "Static Mock", "mock name for metrics")
	mode           = flag.String("mode", "http", "http or https")
	port           = flag.String("port", "9091", "listen port")
	crt            = flag.String("crt", "./ssl/mock.crt", "crt path")
	key            = flag.String("key", "./ssl/mock.key", "key path")
	configFile     = flag.String("config", "config.yml", "path to conig file")
	writeTimeout   = flag.Int64("writeTimeout", 15, "http server write timeout in seconds")
	readTimeout    = flag.Int64("readTimeout", 15, "http server read timeout in seconds")
	idleTimeout    = flag.Int64("idleTimeout", 60, "http server idle timeout in seconds")
	generateConfig = flag.Bool("generateConfig", false, "prints sample config")
)

var (
	router = mux.NewRouter()

	ipAddress string

	config []Config
)

var (
	requestsDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "mock_requests_duration_ms",
			Help:       "A summary of the handling duration of requests.",
			Objectives: map[float64]float64{0.9: 0.01},
			MaxAge:     10 * time.Second,
		},
		[]string{"mock", "host", "port", "path"},
	)

	uptime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mock_uptime",
			Help: "Mock uptime.",
		},
		[]string{"mock", "host", "port"},
	)
)

func init() {
	prometheus.MustRegister(requestsDuration)
	prometheus.MustRegister(uptime)
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())

	ipAddress = getIPAddress()

	getConfig()

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)
}

func main() {
	flag.Parse()

	if *generateConfig {
		config = []Config{
			Config{
				Handler:      "/api/v1",
				ResponseFile: "./resources/response.json",
			},
			Config{
				Handler:      "/api/v2",
				ResponseFile: "./resources/response.xml",
				ResponseTime: ResponseTime{
					Deviation: 100,
					Mean:      30,
				},
				ErrorRate: 0.05,
			},
		}

		sampleConfig, _ := yaml.Marshal(config)
		fmt.Printf("%s", sampleConfig)
		return
	}

	start := time.Now()
	go func() {
		for {
			uptime.WithLabelValues(*mockName, ipAddress, *port).Set(float64(time.Since(start).Milliseconds()))
			time.Sleep(time.Duration(1000 * time.Millisecond))
		}
	}()

	for i := 0; i < len(config); i++ {
		router.HandleFunc(config[i].Handler, middleware(fileHandler(config[i].ResponseFile), config[i]))
	}

	router.Handle("/metrics", promhttp.Handler())
	router.PathPrefix("/").HandlerFunc(defaultHandler)

	srv := &http.Server{
		Addr:         "0.0.0.0:" + *port,
		WriteTimeout: time.Second * time.Duration(*writeTimeout),
		ReadTimeout:  time.Second * time.Duration(*readTimeout),
		IdleTimeout:  time.Second * time.Duration(*idleTimeout),
		Handler:      router,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		switch *mode {
		case "http":
			log.Fatal(srv.ListenAndServe())
		case "https":
			log.Fatal(srv.ListenAndServeTLS(*crt, *key))
		}
	}()

	log.Infof("Starting %s on %s://%s:%s\n", *mockName, *mode, ipAddress, *port)

	<-done
	log.Info("Mock stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		// Close database, redis, truncate message queues, etc
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %s", err)
	}
	log.Info("Mock exited properly")
}
