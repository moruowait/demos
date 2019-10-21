package main

import (
	"log"
	"time"

	"contrib.go.opencensus.io/exporter/stackdriver"
	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/trace"
)

var smokeTest = "smoke-test"
var integrationTest = "integration-test"

var (
	projectID = "gcp-test-195721"
)

func main() {
	e, err := stackdriver.NewExporter(stackdriver.Options{
		ProjectID:         projectID,
		ReportingInterval: 2 * time.Second,
	})
	if err != nil {
		log.Printf("Failed to new stackdriver exporter with projectID: %s", projectID)
		return
	}
	trace.RegisterExporter(e)
	e.StartMetricsExporter()
	defer e.StopMetricsExporter()

	r := metric.NewRegistry()
	metricproducer.GlobalManager().AddProducer(r)
	latencyGauge, err := r.AddFloat64Gauge(
		"buildkite/build_waiting_latency_gauge_mock",
		metric.WithDescription("The build waiting latency in seconds"),
		metric.WithUnit(metricdata.UnitDimensionless),
		metric.WithLabelKeys("pipeline"))
	if err != nil {
		log.Printf("Failed to create gauge: %v", "buildkite/build_waiting_latency_gauge_mock")
		return
	}
	for _, d := range smokeTestData() {
		entry, err := latencyGauge.GetEntry(metricdata.NewLabelValue(d.pipeline))
		if err != nil {
			log.Printf("Failed to get entry, pipeline %v", d.pipeline)
			continue
		}
		entry.Set(d.waitingLatency)
		time.Sleep(40 * time.Second)
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
