package main

import (
	"context"
	"github.com/cilium/ebpf/rlimit"
	"github.com/emilgelman/ig/pkg/opa"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/emilgelman/ig/pkg/enricher"
	"github.com/emilgelman/ig/pkg/export"
	"github.com/emilgelman/ig/pkg/tracer/exec"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func main() {

	ctx := context.Background()
	isDebug := os.Getenv("DEBUG")
	debug, _ := strconv.ParseBool(isDebug)
	if !debug {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatalf("rlimit.RemoveMemlock() failed: %v", err)
		}
	}
	err := host.Init(host.Config{AutoMountFilesystems: true})
	if err != nil {
		log.Fatalf("host.Init() failed: %v", err)
	}

	e, err := enricher.New(enricher.Config{Debug: debug})
	if err != nil {
		log.Fatalf("failed to create enricher: %v", err)
	}

	events := make(chan *types.Event)

	callback := func(event *types.Event) {
		events <- event
	}
	execTracer, err := exec.New(e.Enricher(), callback)
	if err != nil {
		log.Fatalf("failed to create exec tracer: %v", err)
	}

	defer execTracer.Stop()

	exportEvents := make(chan *export.Event)
	opaService, err := opa.New(opa.Config{NumWorkers: 10}, events, exportEvents)
	if err != nil {
		log.Fatalf("failed to run opa: %v", err)
	}

	go func() {
		err := opaService.Evaluate(ctx)
		if err != nil {
			log.Fatalf("failed exporting: %v", err)
		}
	}()

	done := make(chan struct{})
	exporter := export.New(exportEvents, done)
	go func() {
		err := exporter.Export()
		if err != nil {
			log.Fatalf("failed exporting: %v", err)
		}
	}()

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
