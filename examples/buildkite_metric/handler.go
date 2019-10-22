package metric

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"contrib.go.opencensus.io/exporter/stackdriver"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

const (
	buildRunning  = "build.running"
	buildFinished = "build.finished"
)

var (
	tagPipeline             = tag.MustNewKey("pipeline")
	buildWaitingLatency     = stats.Float64("buildkite/build_waiting_latency", "The build waiting latency in seconds", stats.UnitSeconds)
	buildWaitingLatencyView = view.View{
		Name:        buildWaitingLatency.Name(),
		Description: "The distribution of the build waiting latency",
		Measure:     buildWaitingLatency,
		TagKeys:     []tag.Key{tagPipeline},
		Aggregation: view.Distribution(1, 2, 4, 8, 16, 32, 64, 120, 180, 360, 720),
	}
	exporterFlushInterval = 5 * time.Second
	projectID             = "gcp-test-195721"
)

func init() {
	if err := view.Register(&buildWaitingLatencyView); err != nil {
		log.Printf("Failed to register view: %s", buildWaitingLatencyView.Name)
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
	go func() {
		t := time.NewTicker(exporterFlushInterval)
		for {
			select {
			case <-t.C:
				e.Flush()
			}
		}
	}()
}

type buildkiteEvent struct {
	Build    build    `json:"build"`
	Pipeline pipeline `json:"pipeline"`
}

type build struct {
	State       string    `json:"state"`
	ScheduledAt time.Time `json:"scheduled_at"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
}

type pipeline struct {
	Slug string `json:"slug"`
}

// HandleWebhook handles a buildkite webhook request.
func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	var be buildkiteEvent
	if err := json.NewDecoder(r.Body).Decode(&be); err != nil {
		log.Printf("Failed to decode requestBody: %v", err)
		return
	}
	mutators := []tag.Mutator{tag.Upsert(tagPipeline, be.Pipeline.Slug)}
	switch r.Header.Get("X-Buildkite-Event") {
	case buildRunning:
		d := be.Build.StartedAt.Sub(be.Build.ScheduledAt)
		if err := stats.RecordWithTags(context.Background(), mutators, buildWaitingLatency.M(d.Seconds())); err != nil {
			log.Printf("Failed to record stats: %f with pipeline %s", d.Seconds(), be.Pipeline.Slug)
			return
		}
		return
	case buildFinished:
		if be.Build.State != "canceled" {
			return
		}
		d := be.Build.FinishedAt.Sub(be.Build.ScheduledAt)
		if err := stats.RecordWithTags(context.Background(), mutators, buildWaitingLatency.M(d.Seconds())); err != nil {
			log.Printf("Failed to record stats: %f with pipeline %s", d.Seconds(), be.Pipeline.Slug)
			return
		}
		return
	}
}
