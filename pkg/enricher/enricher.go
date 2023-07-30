package enricher

import (
	"os"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

type Enricher struct {
	config              Config
	containerCollection *containercollection.ContainerCollection
}

func New(config Config) (*Enricher, error) {
	containerCollection := &containercollection.ContainerCollection{}

	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, err
	}
	defer tracerCollection.Close()

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(tracerCollection),

		containercollection.WithLinuxNamespaceEnrichment(),

		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutils.RuntimeConfig{
				{Name: "containerd"},
			}),
	}

	if !config.Debug {
		opts = append(opts, containercollection.WithKubernetesEnrichment(os.Getenv("NODE_NAME"), nil))
	}

	if err := containerCollection.Initialize(opts...); err != nil {
		return nil, err
	}
	return &Enricher{containerCollection: containerCollection}, nil
}

func (e *Enricher) Close() {
	e.containerCollection.Close()
}

func (e *Enricher) Enricher() *containercollection.ContainerCollection {
	return e.containerCollection
}
