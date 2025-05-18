package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"example.com/internal"

	"github.com/aquasecurity/libbpfgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var execCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vulnfunc_executions",
		Help: "Times VulnerableFunc was executed",
	},
	[]string{"func"},
)

func init() {
	prometheus.MustRegister(execCounter)
}

func main() {
	// 1) Load static CVE data
	data, err := ioutil.ReadFile("govuln.json")
	if err != nil {
		log.Fatalf("failed to read govuln.json: %v", err)
	}
	gov, err := internal.ParseGovulnJSON(data)
	if err != nil {
		log.Fatalf("failed to parse govuln.json: %v", err)
	}
	_ = gov // later correlation

	// 2) Load & verify BPF object
	module, err := libbpfgo.NewModuleFromFile("hook_funcs.bpf.o")
	log.Println("I was here, module iunitialised NewModuleFromFile")
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}
	defer module.Close()

	if err := module.BPFLoadObject(); err != nil {
		log.Fatalf("failed to load BPF into kernel: %v", err)
	}

	// 3) Retrieve the BPF program by section name
	prog, err := module.GetProgram("trace_vuln") // must match SEC() in your .c
	if err != nil {
		log.Fatalf("failed to find BPF program: %v", err)
	}

	// 4) Attach the uprobe (offset=0 on the symbol)
	_, err = prog.AttachUprobe(-1, os.Args[1], 0)
	if err != nil {
		log.Fatalf("failed to attach uprobe: %v", err)
	}

	// 5) Set up perf buffer channels
	events := make(chan []byte)
	lost := make(chan uint64)
	pb, err := module.InitPerfBuf("events", events, lost, 64)
	if err != nil {
		log.Fatalf("failed to init perf buffer: %v", err)
	}
	pb.Start()
	defer pb.Stop()

	// 6) Expose Prometheus metrics
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":2112", nil))
	}()

	// 7) Handle events & OS signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case data := <-events:
			var name [64]byte
			copy(name[:], data[:64])
			funcName := string(bytes.Trim(name[:], "\x00"))
			execCounter.WithLabelValues(funcName).Inc()
			log.Printf("Executed: %s", funcName)

		case lostCount := <-lost:
			log.Printf("lost %d events\n", lostCount)

		case <-sig:
			log.Println("shutdown signal received, exiting")
			return
		}
	}
}
