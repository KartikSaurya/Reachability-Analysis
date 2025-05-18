package main

// import (
// 	"bufio"
// 	"fmt"
// 	"os"
// 	"strings"
// )

// func main() {
// 	input := "govuln.json"
// 	output := "govuln_fixed.json"

// 	in, err := os.Open(input)
// 	if err != nil {
// 		fmt.Println("Error opening input file:", err)
// 		return
// 	}
// 	defer in.Close()

// 	out, err := os.Create(output)
// 	if err != nil {
// 		fmt.Println("Error creating output file:", err)
// 		return
// 	}
// 	defer out.Close()

// 	scanner := bufio.NewScanner(in)
// 	var objects []string
// 	var current strings.Builder
// 	openBraces := 0

// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		trim := strings.TrimSpace(line)
// 		if trim == "" {
// 			continue
// 		}
// 		// Count braces to detect object boundaries
// 		openBraces += strings.Count(line, "{")
// 		openBraces -= strings.Count(line, "}")
// 		current.WriteString(line + "\n")
// 		if openBraces == 0 && current.Len() > 0 {
// 			objects = append(objects, strings.TrimSpace(current.String()))
// 			current.Reset()
// 		}
// 	}
// 	if err := scanner.Err(); err != nil {
// 		fmt.Println("Error reading file:", err)
// 		return
// 	}

// 	// Write as a JSON array
// 	out.WriteString("[\n")
// 	for i, obj := range objects {
// 		out.WriteString(obj)
// 		if i != len(objects)-1 {
// 			out.WriteString(",\n")
// 		}
// 	}
// 	out.WriteString("\n]\n")

// 	fmt.Println("Fixed JSON written to", output)
// }
