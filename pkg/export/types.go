package export

import "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

type Event struct {
	Rule      string
	ExecEvent *types.Event
}
