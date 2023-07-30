package export

import (
	"fmt"
	"time"
)

type Exporter struct {
	events chan *Event
	done   chan struct{}
}

func New(events chan *Event, done chan struct{}) *Exporter {
	return &Exporter{events: events, done: done}
}

func (e *Exporter) Export() error {
	for {
		select {
		case event := <-e.events:
			fmt.Printf("%s\tRule: %s\tEvent: %+v\n", time.Now().UTC(), event.Rule, *event.ExecEvent)
		case <-e.done:
			return nil
		}
	}
}
