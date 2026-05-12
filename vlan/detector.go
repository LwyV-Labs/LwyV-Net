package vlan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/flowagg"
)

type DetectionResult struct {
	OK                  bool    `json:"ok"`
	FlowID              string  `json:"flow_id"`
	PredictedLabel      string  `json:"predicted_label"`
	PredictedIndex      int     `json:"predicted_index"`
	Confidence          float64 `json:"confidence"`
	MissingFeatureCount int     `json:"missing_feature_count"`
	Error               string  `json:"error"`
}

func sendFeatureToDetector(client *http.Client, feature flowagg.FeatureJSON) (*DetectionResult, error) {
	body, err := json.Marshal(feature)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:8000/predict?top_k=3",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("detector status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result DetectionResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func newDetectorHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
	}
}

func (c *Client) detectorWorker(ch <-chan flowagg.FeatureJSON) {
	client := newDetectorHTTPClient()

	for f := range ch {
		result, err := sendFeatureToDetector(client, f)
		if err != nil {
			//log.Printf("模型检测请求失败: flow=%s err=%v", f.FlowID, err)
			continue
		}

		if !result.OK {
			//log.Printf("模型检测失败: flow=%s err=%s", f.FlowID, result.Error)
			continue
		}

		//log.Printf(
		//	"模型检测结果: flow=%s label=%s confidence=%.4f missing=%d",
		//	result.FlowID,
		//	result.PredictedLabel,
		//	result.Confidence,
		//	result.MissingFeatureCount,
		//)
	}
}
