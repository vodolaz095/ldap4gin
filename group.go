package ldap4gin

type Group struct {
	GID         string // gidNumber
	Name        string // cn
	Description string // description
}

var defaultGroupFields = []string{
	"gidNumber", "cn", "description",
}
