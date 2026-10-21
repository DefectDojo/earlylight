// Package rpmdb lets pkgdb read rpm sqlite databases (rpmdb.sqlite, rpm 4.16
// and later: RHEL 9, Fedora 33+, Amazon Linux 2023, SLES 16). Blank-import it:
//
//	import _ "github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb/rpmdb"
//
// It is separate so that importers of pkgdb that never read rpm databases do
// not link a SQL engine. It only reads rows; header parsing stays in pkgdb.
package rpmdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"

	// Registers the pure-Go "sqlite" database/sql driver (modernc via glebarez),
	// the one go-rpmdb uses.
	_ "github.com/glebarez/go-sqlite"
)

func init() { pkgdb.RegisterRPMSQLiteReader(Read) }

// Limits for hostile databases.
const (
	maxRows    = 1 << 20
	maxBlob    = 0x0fffffff + 8 + 0xffff*16 // rpm's own header size limit
	maxTotal   = 4 << 30
	readTimout = 2 * time.Minute
)

// Read returns every row of the Packages table of an rpm sqlite database. The
// database (and its write-ahead log, which can hold committed transactions not
// yet checkpointed into the main file) is copied into a private temporary
// directory, opened there and removed afterwards; the original is never
// touched. Any error, including a malformed page anywhere in the table,
// fails the whole read: a partial package list is never returned.
func Read(main, wal []byte) (recs []pkgdb.RPMRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			recs, err = nil, fmt.Errorf("sqlite reader failed: %v", r)
		}
	}()
	if err := checkSize(main); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "php2shell-rpmdb-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	db := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(db, main, 0o600); err != nil {
		return nil, err
	}
	if wal != nil {
		if err := os.WriteFile(db+"-wal", wal, 0o600); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + (&url.URL{Path: db}).EscapedPath() +
		"?_pragma=trusted_schema(0)&_pragma=cell_size_check(1)"
	h, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	h.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), readTimout)
	defer cancel()

	var typ string
	if err := h.QueryRowContext(ctx, "SELECT type FROM sqlite_master WHERE name = 'Packages'").Scan(&typ); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("no Packages table")
		}
		return nil, err
	}
	if typ != "table" {
		return nil, fmt.Errorf("Packages is a %s, not a table", typ)
	}
	if _, err := h.ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
		return nil, err
	}
	var check string
	if err := h.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil {
		return nil, fmt.Errorf("integrity check: %w", err)
	}
	if check != "ok" {
		return nil, fmt.Errorf("integrity check: %s", check)
	}
	rows, err := h.QueryContext(ctx, "SELECT hnum, blob FROM Packages")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var key int64
		var blob []byte
		if err := rows.Scan(&key, &blob); err != nil {
			return nil, err
		}
		if key <= 0 || key > 1<<32-1 {
			return nil, fmt.Errorf("row with package number %d", key)
		}
		if len(blob) > maxBlob {
			return nil, fmt.Errorf("package %d: header of %d bytes exceeds rpm's limit", key, len(blob))
		}
		if total += len(blob); total > maxTotal || len(recs) >= maxRows {
			return nil, errors.New("database too large")
		}
		recs = append(recs, pkgdb.RPMRecord{Key: uint32(key), Blob: blob})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return recs, nil
}

// checkSize rejects a database file shorter than its header says (SQLite
// would read the missing bytes as zeros).
func checkSize(b []byte) error {
	if len(b) < 100 || string(b[:16]) != "SQLite format 3\x00" {
		return errors.New("not an SQLite database")
	}
	psize := int(b[16])<<8 | int(b[17])
	if psize == 1 {
		psize = 65536
	}
	if psize < 512 || psize&(psize-1) != 0 {
		return fmt.Errorf("bad page size %d", psize)
	}
	if len(b)%psize != 0 {
		return fmt.Errorf("file size %d is not a multiple of the page size %d (truncated)", len(b), psize)
	}
	pages := int(b[28])<<24 | int(b[29])<<16 | int(b[30])<<8 | int(b[31])
	validFor := string(b[92:96])
	if validFor == string(b[24:28]) && pages > 0 && len(b) < pages*psize {
		return fmt.Errorf("file has %d bytes, header says %d pages of %d (truncated)", len(b), pages, psize)
	}
	return nil
}
