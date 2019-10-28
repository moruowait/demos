package main

import (
	"context"
	"log"
	"time"

	"contrib.go.opencensus.io/exporter/stackdriver"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

const (
	smokeTest       = "smoke-test"
	integrationTest = "integration-test"
)

var (
	tagPipeline             = tag.MustNewKey("pipeline")
	buildWaitingLatency     = stats.Float64("buildkite/build_waiting_latency_mock", "The build waiting latency in seconds", stats.UnitSeconds)
	buildWaitingLatencyView = view.View{
		Name:        buildWaitingLatency.Name(),
		Description: "The distribution of the build waiting latency mock",
		Measure:     buildWaitingLatency,
		TagKeys:     []tag.Key{tagPipeline},
		Aggregation: view.Distribution(1, 2, 4, 8, 16, 32, 64, 120, 180, 360, 720),
	}
	projectID = "gcp-test-195721"
)

func main() {
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
	defer e.Flush()
	view.SetReportingPeriod(10 * time.Second)
	view.RegisterExporter(e)

	for _, d := range smokeTestData() {
		mutators := []tag.Mutator{tag.Upsert(tagPipeline, d.pipeline)}
		ctx, err := tag.New(context.Background(), mutators...)
		if err != nil {
			continue
		}
		time.Sleep(20 * time.Second)
		stats.Record(ctx, buildWaitingLatency.M(d.waitingLatency))
		log.Printf("record %s with %f", d.pipeline, d.waitingLatency)
	}
	var c chan int
	<-c
}

type testdata struct {
	waitingLatency float64
	pipeline       string
}

var smokeTestLatency = []float64{100, 150, 100, 150, 100, 80, 20, 10, 40, 80, 150, 250, 260, 300, 160, 30, 20, 20, 150, 200, 180, 400, 250, 200, 140, 30, 20}

func smokeTestData() []testdata {
	var smokeTestData []testdata
	for _, std := range smokeTestLatency {
		smokeTestData = append(smokeTestData, testdata{
			waitingLatency: std,
			pipeline:       smokeTest,
		})
	}
	return smokeTestData
}
