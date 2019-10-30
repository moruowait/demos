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
	tagPipeline      = tag.MustNewKey("pipeline")
	tagGroupName     = tag.MustNewKey("group_name")
	allBuildTask     = stats.Int64("buildkite/all_build_task", "The build waiting latency in seconds", stats.UnitDimensionless)
	allBuildTaskView = view.View{
		Name:        allBuildTask.Name(),
		Description: "The distribution of all build task mock",
		Measure:     allBuildTask,
		TagKeys:     []tag.Key{tagPipeline, tagGroupName},
		Aggregation: view.Distribution(1, 2, 4, 8, 16, 32, 64, 120, 180, 360, 720),
	}
	projectID = "gcp-test-195721"
	groupName = "instance-group-autoscale-1"
)

func main() {
	if err := view.Register(&allBuildTaskView); err != nil {
		log.Printf("Failed to register view: %s", allBuildTaskView.Name)
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
		mutators := []tag.Mutator{
			tag.Upsert(tagPipeline, d.pipeline),
			tag.Upsert(tagGroupName, groupName),
		}
		ctx, err := tag.New(context.Background(), mutators...)
		if err != nil {
			continue
		}
		time.Sleep(20 * time.Second)
		stats.Record(ctx, allBuildTask.M(d.taskNum))
		log.Printf("record %s with %d", d.pipeline, d.taskNum)
	}
	var c chan int
	<-c
}

type testdata struct {
	taskNum  int64
	pipeline string
}

var smokeTestLatency = []int64{1, 2, 3, 4, 3, 2, 2, 2, 1, 0, 0, 1, 1, 2, 3, 4, 5, 3, 2, 1, 0}

func smokeTestData() []testdata {
	var smokeTestData []testdata
	for _, std := range smokeTestLatency {
		smokeTestData = append(smokeTestData, testdata{
			taskNum:  std,
			pipeline: smokeTest,
		})
	}
	return smokeTestData
}
