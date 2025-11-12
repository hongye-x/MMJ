package test

import (
	"fmt"
	b "sig_vfy/src/base"
	"sig_vfy/src/keymanage"
	"sig_vfy/src/sqlop"
	"testing"
)

func TestDestorySql(t *testing.T) {
	sqlop.SqlDestroy()
}

func TestCreateSql(t *testing.T) {
	err := sqlop.SqlCreate()
	if err != nil {
		b.PrintStdErr(err)
	}
}

func TestConn2Sql(t *testing.T) {
	err := sqlop.SqlConnect()
	if err != nil {
		b.PrintStdErr(err)
	}
}

func TestGetKeyList(t *testing.T) {
	n, stderr := keymanage.GetKeyListFromSQL(0)
	if stderr != nil {
		b.PrintStdErr(stderr)
		t.Logf("")

	}
	fmt.Println("symlist ", n)

	n, stderr = keymanage.GetKeyListFromSQL(2)
	if stderr != nil {
		b.PrintStdErr(stderr)
		t.Logf("")

	}
	fmt.Println("sm2enclist ", n)
}
