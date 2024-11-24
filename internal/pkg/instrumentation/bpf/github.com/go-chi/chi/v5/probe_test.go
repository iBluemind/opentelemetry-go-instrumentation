// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chi

import (
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/utils"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
)

func TestProbeConvertEvent(t *testing.T) {
	startTime := time.Unix(0, time.Now().UnixNano()) // No wall clock.
	endTime := startTime.Add(1 * time.Second)

	startTimeOffset := utils.TimeToBootOffset(startTime)
	endTimeOffset := utils.TimeToBootOffset(endTime)

	traceID := trace.TraceID{1}
	spanID := trace.SpanID{1}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	testCases := []struct {
		name     string
		event    *event
		expected []*probe.SpanEvent
	}{
		{
			name: "basic client event",
			event: &event{
				BaseSpanProperties: context.BaseSpanProperties{
					StartTime:   startTimeOffset,
					EndTime:     endTimeOffset,
					SpanContext: context.EBPFSpanContext{TraceID: traceID, SpanID: spanID},
				},
				// "GET"
				Method: [8]byte{0x47, 0x45, 0x54},
				// "/foo/bar"
				Path: [128]byte{0x2f, 0x66, 0x6f, 0x6f, 0x2f, 0x62, 0x61, 0x72},
				// "/foo/bar"
				PathPattern: [128]byte{0x2f, 0x66, 0x6f, 0x6f, 0x2f, 0x62, 0x61, 0x72},
			},
			expected: []*probe.SpanEvent{
				{
					SpanName:    "GET",
					StartTime:   startTime,
					EndTime:     endTime,
					SpanContext: &sc,
					Attributes: []attribute.KeyValue{
						semconv.HTTPRequestMethodKey.String("GET"),
						semconv.URLPath("/foo/bar"),
						semconv.HTTPRouteKey.String("/foo/bar"),
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			out := convertEvent(tt.event)
			assert.Equal(t, tt.expected, out)
		})
	}
}
