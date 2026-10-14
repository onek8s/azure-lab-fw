package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Warning is a non-fatal finding while loading policy JSON, e.g. a field that
// labfw does not model (PLAN §4.1: "collect as unknown and warn once").
type Warning struct {
	Path    string `json:"path"`    // JSON path, e.g. policies[0].properties.futureField
	Message string `json:"message"` // human-readable
}

func (w Warning) String() string {
	if w.Path == "" {
		return w.Message
	}
	return w.Path + ": " + w.Message
}

var (
	rawMessageType = reflect.TypeOf(json.RawMessage(nil))
	ruleType       = reflect.TypeOf(Rule{})
)

// fieldIndex caches the JSON field names of struct types (including fields
// promoted from embedded structs).
var fieldIndex sync.Map // reflect.Type -> map[string]reflect.Type

func knownFields(t reflect.Type) map[string]reflect.Type {
	if m, ok := fieldIndex.Load(t); ok {
		return m.(map[string]reflect.Type)
	}
	m := map[string]reflect.Type{}
	collectFields(t, m)
	fieldIndex.Store(t, m)
	return m
}

func collectFields(t reflect.Type, m map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			collectFields(f.Type, m)
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		m[name] = f.Type
	}
}

// lookupField finds a JSON key in a struct type. Like encoding/json, an exact
// match is preferred and a case-insensitive match is accepted.
func lookupField(fields map[string]reflect.Type, key string) (reflect.Type, bool) {
	if ft, ok := fields[key]; ok {
		return ft, true
	}
	for name, ft := range fields {
		if strings.EqualFold(name, key) {
			return ft, true
		}
	}
	return nil, false
}

// findUnknown walks the generic JSON value v alongside the Go type t and
// appends a warning for every object key that t does not model. Opaque
// types (json.RawMessage, interfaces, maps of non-structs) are not descended.
func findUnknown(v any, t reflect.Type, path string, out *[]Warning) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType || t.Kind() == reflect.Interface {
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return
		}
		if t == ruleType {
			findUnknownRule(obj, path, out)
			return
		}
		fields := knownFields(t)
		for _, k := range sortedKeys(obj) {
			ft, ok := lookupField(fields, k)
			if !ok {
				*out = append(*out, Warning{Path: joinKey(path, k), Message: "unknown field (ignored)"})
				continue
			}
			findUnknown(obj[k], ft, joinKey(path, k), out)
		}
	case reflect.Slice, reflect.Array:
		arr, ok := v.([]any)
		if !ok {
			return
		}
		for i, e := range arr {
			findUnknown(e, t.Elem(), path+"["+strconv.Itoa(i)+"]", out)
		}
	case reflect.Map:
		obj, ok := v.(map[string]any)
		if !ok {
			return
		}
		for _, k := range sortedKeys(obj) {
			findUnknown(obj[k], t.Elem(), path+"["+strconv.Quote(k)+"]", out)
		}
	}
}

func findUnknownRule(obj map[string]any, path string, out *[]Warning) {
	rt, _ := obj["ruleType"].(string)
	var t reflect.Type
	switch rt {
	case NatRuleType:
		t = reflect.TypeOf(NatRule{})
	case NetworkRuleType:
		t = reflect.TypeOf(NetworkRule{})
	case ApplicationRuleType:
		t = reflect.TypeOf(ApplicationRule{})
	default:
		*out = append(*out, Warning{Path: joinKey(path, "ruleType"), Message: fmt.Sprintf("unknown ruleType %q (rule kept verbatim, not interpreted)", rt)})
		return
	}
	findUnknown(obj, t, path, out)
}

func joinKey(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
