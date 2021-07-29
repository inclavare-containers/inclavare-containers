package main

import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/open-policy-agent/opa/rego"
)

//export makeDecisionGo
func makeDecisionGo(policy string, message string) *C.char {

	// Deserialize the message in json format
	message_map := make(map[string]string)
	err := json.Unmarshal([]byte(message), &message_map)
	if err != nil {
		log.Fatal(err)
		return C.CString("")
	}

	// Construct a Rego object that can be prepared or evaluated.
	r := rego.New(
		rego.Query("input;data.policy"),
		rego.Module("demo.rego", policy),
	)

	// Create a prepared query that can be evaluated.
	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		log.Fatal(err)
		return C.CString("")
	}

	// Make opa query
	rs, err := query.Eval(ctx, rego.EvalInput(message_map))
	if err != nil {
		log.Fatal(err)
		return C.CString("")
	}

	// Transform the processed decision into the format rust hopes for
	input := rs[0].Expressions[0].Value.(map[string]interface{})
	dataDemo := rs[0].Expressions[1].Value.(map[string]interface{})
	parseInfo := make(map[string]interface{})

	for k, v := range input {
		value := [2]interface{}{v, dataDemo[k]}
		parseInfo[k] = value
	}

	decisionMap := make(map[string]interface{})
	decisionMap["parseInfo"] = parseInfo
	decisionMap["allow"] = dataDemo["allow"]

	decision, err := json.Marshal(decisionMap)
	if err != nil {
		fmt.Println("json.Marshal failed: ", err)
		return C.CString("")
	}

	return C.CString(string(decision))
}

func main() {}
