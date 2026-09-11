// Command printrows prints n rows from the ULPF SQLite DB.
//
// Usage:
//
//	go run ./src/printrows -n 10 -db ulpf.db
//	go run ./src/printrows -n 50 -since 1000 -db ulpf.db
//	go run ./src/printrows -n 5 -json -db ulpf.db
//
// Flags:
//
//	-db    path to SQLite file (default "ulpf.db")
//	-n     number of rows to print (default 10, must be > 0)
//	-since only print rows with id > since (default 0)
//	-json  print full OCSF JSON per row instead of a one-line summary
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"sih/src/output"
)

func main() {
	dbPath := flag.String("db", "ulpf.db", "path to SQLite DB file")
	n := flag.Int("n", 10, "number of rows to print")
	since := flag.Int64("since", 0, "only print rows with id > since")
	asJSON := flag.Bool("json", false, "print full OCSF JSON per row")
	flag.Parse()

	if *n <= 0 {
		fmt.Fprintf(os.Stderr, "printrows: -n must be > 0, got %d\n", *n)
		flag.Usage()
		os.Exit(2)
	}

	store, err := output.OpenSQLite(*dbPath)
	if err != nil {
		log.Fatalf("open db %q: %v", *dbPath, err)
	}
	defer store.Close()

	ctx := context.Background()
	remaining := *n
	cursor := *since
	printed := 0

	enc := json.NewEncoder(os.Stdout)

	for remaining > 0 {
		limit := remaining
		if limit > 5000 {
			limit = 5000 // EventsSince clamps to 5000; page through
		}
		rows, err := store.EventsSince(ctx, cursor, limit)
		if err != nil {
			log.Fatalf("query: %v", err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if *asJSON {
				if err := enc.Encode(r.Event); err != nil {
					log.Fatalf("encode: %v", err)
				}
			} else {
				e := r.Event
				fmt.Printf("id=%d time=%s class=%d src=%s:%d dst=%s:%d proto=%s action=%s sev=%d uid=%s msg=%q\n",
					r.ID, e.TimeRFC3339(), e.ClassUID,
					e.SrcEndpoint.IP, e.SrcEndpoint.Port,
					e.DstEndpoint.IP, e.DstEndpoint.Port,
					e.ProtocolName, e.Action, e.SeverityID,
					e.EventID(), e.Message)
			}
			cursor = r.ID
			printed++
		}
		remaining = *n - printed
		if len(rows) < limit {
			break
		}
	}

	fmt.Fprintf(os.Stderr, "printed %d row(s) from %s (since=%d requested=%d)\n", printed, *dbPath, *since, *n)
}
