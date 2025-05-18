package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

var count uint64

// Handler for the button click — increments and returns the new count.
func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// allow CORS if you open index.html as file://
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// increment
	newVal := atomic.AddUint64(&count, 1)

	// respond with JSON
	resp := struct{ Count uint64 }{Count: newVal}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Handler to fetch current count
func countHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct{ Count uint64 }{Count: atomic.LoadUint64(&count)})
}

func main() {
	// serve static assets from ./static
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", fs)

	// API endpoints
	http.HandleFunc("/vulnerable", vulnerableHandler)
	http.HandleFunc("/count", countHandler)

	fmt.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
