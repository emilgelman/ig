package exec

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

func New(enricher *containercollection.ContainerCollection, eventCallback func(*types.Event)) (*tracer.Tracer, error) {
	t, err := tracer.NewTracer(&tracer.Config{GetCwd: true}, enricher, eventCallback)
	if err != nil {
		return nil, err
	}
	return t, nil
}
