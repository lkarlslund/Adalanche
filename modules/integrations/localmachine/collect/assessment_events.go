package collect

import (
	"encoding/xml"
	"strconv"
)

func projectAssessmentEvent(raw string, passwordMetadata bool) (map[string]any, error) {
	if len(raw) > 1<<20 {
		return nil, errAssessmentLimit
	}
	var event struct {
		XMLName xml.Name `xml:"Event"`
		System  struct {
			ID       uint32 `xml:"EventID"`
			Level    uint32 `xml:"Level"`
			RecordID uint64 `xml:"EventRecordID"`
			Time     struct {
				Value string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
			Correlation struct {
				Activity string `xml:"ActivityID,attr"`
			} `xml:"Correlation"`
		} `xml:"System"`
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"EventData>Data"`
	}
	if err := xml.Unmarshal([]byte(raw), &event); err != nil {
		return nil, err
	}
	r := map[string]any{"Id": event.System.ID, "TimeCreated": event.System.Time.Value, "Level": event.System.Level, "RecordID": event.System.RecordID, "ActivityID": event.System.Correlation.Activity}
	if passwordMetadata {
		for _, data := range event.Data {
			if len(data.Value) > 512 {
				continue
			}
			switch data.Name {
			case "AccountName", "AccountSid", "AccountSID":
				r[data.Name] = data.Value
			case "ErrorCode", "Error", "BackupDirectory":
				if code, err := strconv.ParseUint(data.Value, 0, 64); err == nil {
					r[data.Name] = code
				}
			}
		}
	}
	return r, nil
}
