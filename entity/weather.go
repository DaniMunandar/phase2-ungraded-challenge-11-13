package entity

type Weather struct {
	CloudPct    int     `json:"cloud_pct"`
	Temp        int     `json:"temp"`
	FeelsLike   int     `json:"feels_like"`
	Humidity    int     `json:"humidity"`
	MinTemp     int     `json:"min_temp"`
	MaxTemp     int     `json:"max_temp"`
	WindSpeed   float64 `json:"wind_speed"`
	WindDegrees int     `json:"wind_degrees"`
	Sunrise     int     `json:"sunrise"`
	Sunset      int     `json:"sunset"`
}
