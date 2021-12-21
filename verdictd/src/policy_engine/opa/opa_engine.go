package main

import "C"

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

//export makeDecisionGo
func makeDecisionGo(policy string, data string, input string) *C.char {
	// Deserialize the message in json format
	input_map := make(map[string]interface{})
	err := json.Unmarshal([]byte(input), &input_map)
	if err != nil {
		return C.CString("Unmarshal input error.")
	}

	data_map := make(map[string]interface{})
	err2 := json.Unmarshal([]byte(data), &data_map)
	if err2 != nil {
		// Handle error.
		return C.CString("Unmarshal data error.")
	}
	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(data_map)

	// Construct a Rego object that can be prepared or evaluated.
	r := rego.New(
		rego.Query("input;data.policy"),
		rego.Module("demo.rego", policy),
		rego.Store(store),
	)

	// Create a prepared query that can be evaluated.
	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return C.CString(err.Error())
	}

	// Make opa query
	rs, err := query.Eval(ctx, rego.EvalInput(input_map))
	if err != nil {
		return C.CString(err.Error())
	}

	// Transform the processed decision into the format rust hopes for
	inputOPA := rs[0].Expressions[0].Value.(map[string]interface{})
	dataOPA := rs[0].Expressions[1].Value.(map[string]interface{})
	parseInfo := make(map[string]interface{})

	for k, v := range inputOPA {
		value := [2]interface{}{v, data_map[k]}
		parseInfo[k] = value
	}

	decisionMap := make(map[string]interface{})
	decisionMap["parseInfo"] = parseInfo
	decisionMap["allow"] = dataOPA["allow"]

	decision, err := json.Marshal(decisionMap)
	if err != nil {
		return C.CString("Unmarshal decision error.")
	}
	decision_str := string(decision)
	res := strings.Replace(decision_str, "\\u003e", ">", -1)
	res = strings.Replace(res, "\\u003c", "<", -1)
	
	return C.CString(res)
}

func main() {}
