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
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
	"log/slog"

	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
	"go.opentelemetry.io/auto/internal/pkg/structfield"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./bpf/probe.bpf.c

const (
	// pkg is the package being instrumented.
	pkg = "github.com/go-chi/chi/v5"
)

// New returns a new [probe.Probe].
func New(logger *slog.Logger) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindServer,
		InstrumentedPkg: pkg,
	}
	return &probe.Base[bpfObjects, event]{
		ID:     id,
		Logger: logger,
		Consts: []probe.Const{
			probe.RegistersABIConst{},
			probe.StructFieldConst{
				Key: "method_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "Method"),
			},
			probe.StructFieldConst{
				Key: "url_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "URL"),
			},
			probe.StructFieldConst{
				Key: "ctx_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "ctx"),
			},
			probe.StructFieldConst{
				Key: "path_ptr_pos",
				Val: structfield.NewID("std", "net/url", "URL", "Path"),
			},
			probe.StructFieldConst{
				Key: "val_ptr_pos",
				Val: structfield.NewID("std", "context", "valueCtx", "val"),
			},
			probe.StructFieldConst{
				Key: "rp_str_pos",
				Val: structfield.NewID("github.com/go-chi/chi/v5", "github.com/go-chi/chi/v5", "Context", "routePattern"),
			},
		},
		Uprobes: []probe.Uprobe{
			{
				Sym:         "github.com/go-chi/chi/v5.(*Mux).routeHTTP",
				EntryProbe:  "uprobe_chi_Mux_routeHTTP",
				ReturnProbe: "uprobe_chi_Mux_routeHTTP_Returns",
			},
		},
		SpecFn:    loadBpf,
		ProcessFn: convertEvent,
	}
}

// event represents an event in the chi server during an HTTP
// request-response.
type event struct {
	context.BaseSpanProperties
	Method      [8]byte
	Path        [128]byte
	PathPattern [128]byte
}

func convertEvent(e *event) []*probe.SpanEvent {
	method := unix.ByteSliceToString(e.Method[:])
	path := unix.ByteSliceToString(e.Path[:])
	patternPath := unix.ByteSliceToString(e.PathPattern[:])

	attributes := []attribute.KeyValue{
		semconv.HTTPRequestMethodKey.String(method),
		semconv.URLPath(path),
	}

	if patternPath != "" {
		attributes = append(attributes, semconv.HTTPRouteKey.String(patternPath))
	}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    e.SpanContext.TraceID,
		SpanID:     e.SpanContext.SpanID,
		TraceFlags: trace.FlagsSampled,
	})

	var pscPtr *trace.SpanContext
	if e.ParentSpanContext.TraceID.IsValid() {
		psc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    e.ParentSpanContext.TraceID,
			SpanID:     e.ParentSpanContext.SpanID,
			TraceFlags: trace.FlagsSampled,
			Remote:     true,
		})
		pscPtr = &psc
	} else {
		pscPtr = nil
	}

	spanEvent := &probe.SpanEvent{
		SpanName:          method,
		StartTime:         utils.BootOffsetToTime(e.StartTime),
		EndTime:           utils.BootOffsetToTime(e.EndTime),
		SpanContext:       &sc,
		Attributes:        attributes,
		ParentSpanContext: pscPtr,
	}

	return []*probe.SpanEvent{spanEvent}
}
