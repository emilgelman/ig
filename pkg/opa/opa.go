package opa

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/emilgelman/ig/pkg/export"
)

type Opa struct {
	config       Config
	events       chan *types.Event
	exportEvents chan *export.Event
	query        rego.PreparedEvalQuery
}

func New(config Config, events chan *types.Event, exportEvents chan *export.Event) (*Opa, error) {
	// Load OPA rules from file
	bs, err := os.ReadFile("rules/rules.rego")
	if err != nil {
		return nil, err
	}

	// Compile OPA rules
	rules, err := ast.ParseModule("rules.rego", string(bs))
	if err != nil {
		return nil, err
	}

	bs, err = os.ReadFile("rules/macros.rego")
	if err != nil {
		return nil, err
	}

	// Compile OPA rules
	macros, err := ast.ParseModule("macros.rego", string(bs))
	if err != nil {
		return nil, err
	}

	compiler := ast.NewCompiler()
	if compiler.Compile(map[string]*ast.Module{"rules.rego": rules, "macros.rego": macros}); compiler.Failed() {
		return nil, err
	}

	// Create OPA query
	query, err := rego.New(
		rego.Query("data.rules"),
		rego.Compiler(compiler),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}

	return &Opa{config: config, events: events, exportEvents: exportEvents, query: query}, nil
}

func (o *Opa) Evaluate(ctx context.Context) error {
	for i := 0; i < o.config.NumWorkers; i++ {
		go o.worker(ctx, i)
	}

	return nil
}

func (o *Opa) worker(ctx context.Context, workerId int) {
	fmt.Printf("starting worker %v\n", workerId)
	for event := range o.events {
		resultSet, err := o.query.Eval(ctx, rego.EvalInput(event))
		if err != nil {
			log.Fatalf("error evaluating query: %v", err)
		}

		if len(resultSet) < 1 {
			return
		}
		m, ok := resultSet[0].Expressions[0].Value.(map[string]interface{})
		if ok {
			for k := range m {
				o.exportEvents <- &export.Event{Rule: k, ExecEvent: event}
				// only export the first matching rule
				break
			}
		}
	}
}
