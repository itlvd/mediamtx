package primitives

import "time"

// DateTime is a RFC3339 datetime.
type DateTime time.Time

// Unmarshal implements Primitive.
func (d *DateTime) Unmarshal(v string) error {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return err
	}
	*d = DateTime(t)
	return nil
}

// Marshal implements Primitive.
func (d DateTime) Marshal() string {
	return time.Time(d).Format(time.RFC3339)
} 