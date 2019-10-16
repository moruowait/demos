package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"log"

	"contrib.go.opencensus.io/exporter/stackdriver"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	buildWaitingLatency     = stats.Float64("build_waiting_latency", "The build waiting latency in minutes", stats.UnitSeconds)
	tagPipeline             = tag.MustNewKey("pipeline")
	projectID               = "gcp-test-195721"
	buildWaitingLatencyView = view.View{
		Name:        "build_waiting_latency_distribution",
		Description: "The distribution of the build waiting latency",
		Measure:     buildWaitingLatency,
		TagKeys:     []tag.Key{tagPipeline},
		Aggregation: view.Distribution(40, 100, 200, 400, 800, 1000),
	}
)

func init() {
	if err := view.Register(&buildWaitingLatencyView); err != nil {
		log.Printf("Failed to register view: ", buildWaitingLatencyView.Name)
		return
	}
	e, err := stackdriver.NewExporter(stackdriver.Options{
		ProjectID: projectID,
	})
	if err != nil {
		log.Printf("Failed to new stackdriver exporter with projectID: %s", projectID)
		return
	}
	view.RegisterExporter(e)
}

type buildkiteEvent struct {
	Build    build    `json:"build"`
	Event    string   `json:"event"`
	Pipeline pipeline `json:"pipeline"`
}

type build struct {
	CreatedAt   time.Time `json:"created_at"`
	ScheduledAt time.Time `json:"scheduled_at"`
	StartedAt   time.Time `json:"started_at"`
}

type pipeline struct {
	Slug string `json:"slug"`
}

// HandleWebhook handles a buildkite webhook request.
func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "hello webhook")
	switch r.Header.Get("X-Buildkite-Event") {
	case "build.running":
		var be buildkiteEvent
		if err := json.NewDecoder(r.Body).Decode(&be); err != nil {
			log.Printf("Failed to decode requestBody: %v", err)
			return
		}
		d := be.Build.StartedAt.Sub(be.Build.ScheduledAt)
		stats.RecordWithTags(context.Background(), []tag.Mutator{tag.Upsert(tagPipeline, be.Pipeline.Slug)}, buildWaitingLatency.M(d.Seconds()))
		return
	}
}
