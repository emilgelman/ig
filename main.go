package main

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"os/signal"
	"syscall"

	execTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	execTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	netTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"

	networkTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	// create tracers
	//tracer, err := createNetworkTracer()
	tracer, err := createProcessCreationTracer()
	if err != nil {
		panic(err)
	}

	defer tracer.Stop()

	// network tracer only
	//defer tracer.Detach(uint32(os.Getpid()))

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}

func networkEventCallback(event *netTypes.Event) {
	eventCallback(event)
}

func execEventCallback(event *execTypes.Event) {
	eventCallback(event)
}

func eventCallback(event any) {
	file, err := os.OpenFile("/tmp/out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	jsonEvent, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	_, err = file.WriteString(fmt.Sprintf("%s\n", jsonEvent))
	if err != nil {
		panic(err)
	}
}

func createProcessCreationTracer() (*execTracer.Tracer, error) {
	tracer, err := execTracer.NewTracer(&execTracer.Config{}, nil, execEventCallback)
	if err != nil {
		return nil, err
	}

	return tracer, nil

}

func createNetworkTracer() (*networkTracer.Tracer, error) {
	tracer, err := networkTracer.NewTracer()
	if err != nil {
		return nil, err
	}
	tracer.SetEventHandler(networkEventCallback)
	// The tracer has to be attached. The packets will be traced on
	// the network namespace of pid.
	pid := uint32(os.Getpid())
	if err := tracer.Attach(pid); err != nil {
		fmt.Printf("error attaching tracer: %s\n", err)
		return nil, err
	}
	return tracer, nil
}
