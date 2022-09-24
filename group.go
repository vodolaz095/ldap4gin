package ldap4gin

// Group is member of groups organization unit in ldap
type Group struct {
	GID         string // gidNumber
	Name        string // cn
	Description string // description
}

var defaultGroupFields = []string{
	"gidNumber", "cn", "description",
}
