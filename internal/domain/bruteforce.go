package domain

type BruteforcePart struct {
	Service  string
	Domain   string
	IP       string
	Port     int
	Username string
	Password string
	IsValid  bool
}
