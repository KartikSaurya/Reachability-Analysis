package main

import (
	"bytes"
	"io"
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

	// Define log file path
	logFilePath := "app.log"

	// Check if log file exists, create it if it doesn't
	_, err := os.Stat(logFilePath)
	if os.IsNotExist(err) {
		// Create the log file
		file, err := os.Create(logFilePath)
		if err != nil {
			log.Fatalf("failed to create log file %s: %v", logFilePath, err)
		}
		file.Close() // Close the file after creation
	} else if err != nil {
		log.Fatalf("failed to check log file %s: %v", logFilePath, err)
	}

	// Open log file for appending
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file %s: %v", logFilePath, err)
	}

	// Log to both file and stdout
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Include timestamp and file:line
}

func main() {
	// Validate command-line arguments
	binaryPath := "/app/server_binary" // Default to container's server_binary
	if len(os.Args) >= 2 {
		binaryPath = os.Args[1]
	}
	log.Printf("Using binary path: %s", binaryPath)

	// Verify binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		log.Fatalf("binary path %s does not exist", binaryPath)
	} else if err != nil {
		log.Fatalf("failed to check binary path %s: %v", binaryPath, err)
	}

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
	log.Printf("Attaching uprobe to binary: %s, symbol: vulnerableHandler", binaryPath)
	link, err := prog.AttachUprobe(-1, binaryPath, 0)
	if err != nil {
		log.Fatalf("failed to attach uprobe: %v", err)
	}
	log.Printf("Uprobe attached successfully, link: %v", link)

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
			log.Printf("Received event, data length: %d", len(data))
			var name [64]byte
			copy(name[:], data[:64])
			funcName := string(bytes.Trim(name[:], "\x00"))
			execCounter.WithLabelValues(funcName).Inc()
			log.Printf("Executed: %s", funcName)

		case lostCount := <-lost:
			log.Printf("Lost %d events", lostCount)

		case <-sig:
			log.Println("shutdown signal received, exiting")
			return
		}
	}
}