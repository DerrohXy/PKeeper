package core

import (
	"database/sql"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"io"
	"os"

	"golang.org/x/crypto/argon2"

	_ "github.com/mattn/go-sqlite3"

	"golang.org/x/crypto/pbkdf2"
)

const DEFAULT_DATABASE_FILE_NAME = "pkeeper.db"

func InitializeDefaultDatabase() (string, error) {
	homeDirectory, err := os.UserHomeDir()
	if err == nil {
		directory := ".pkeeper"
		homeDirectory = filepath.Join(homeDirectory, directory)

		err := os.MkdirAll(homeDirectory, 0755)
		if err == nil {
			databaseFile := filepath.Join(homeDirectory, DEFAULT_DATABASE_FILE_NAME)
			database, err := GetDatabase(databaseFile)
			if err != nil {
				return "", err
			}

			database.Close()

			return databaseFile, nil
		}

		return "", err
	}

	return "", err
}

func FindDatabaseFile() (string, error) {
	const fileName = DEFAULT_DATABASE_FILE_NAME

	homeDirectory, err := InitializeDefaultDatabase()
	if err == nil {
		workingPath := filepath.Join(homeDirectory, fileName)

		info, err := os.Stat(workingPath)
		if err == nil && !info.IsDir() {
			abs, err := filepath.Abs(workingPath)
			if err == nil {
				return abs, nil
			}

			return workingPath, nil
		}
	}

	workingDirectory, err := os.Getwd()
	if err == nil {
		workingPath := filepath.Join(workingDirectory, fileName)

		info, err := os.Stat(workingPath)
		if err == nil && !info.IsDir() {
			abs, err := filepath.Abs(workingPath)
			if err == nil {
				return abs, nil
			}

			return workingPath, nil
		}
	}

	executablePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	exeDir := filepath.Dir(executablePath)
	dbPath := filepath.Join(exeDir, fileName)

	info, err := os.Stat(dbPath)
	if err == nil && !info.IsDir() {
		abs, err := filepath.Abs(dbPath)
		if err == nil {
			return abs, nil
		}

		return dbPath, nil
	}

	return "", fmt.Errorf("Database file not found")
}

const (
	saltSize = 16
	keySize  = 32
	iter     = 100_000
)

func EncryptText(password, plaintext string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(password), salt, iter, keySize, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	output := append(salt, nonce...)
	output = append(output, ciphertext...)

	return base64.StdEncoding.EncodeToString(output), nil
}

func DecryptText(password, encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	salt := data[:saltSize]

	key := pbkdf2.Key([]byte(password), salt, iter, keySize, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLength          = 16
)

func HashText(plaintext string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(plaintext),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=19$t=%d,m=%d,p=%d$%s$%s",
		argonTime,
		argonMemory,
		argonThreads,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

func VerifyHashedText(plaintext, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	var memory uint32
	var time uint32
	var threads uint8

	_, err := fmt.Sscanf(
		parts[3],
		"t=%d,m=%d,p=%d",
		&time,
		&memory,
		&threads,
	)
	if err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	originalHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	newHash := argon2.IDKey(
		[]byte(plaintext),
		salt,
		time,
		memory,
		threads,
		uint32(len(originalHash)),
	)

	return subtle.ConstantTimeCompare(originalHash, newHash) == 1
}

func GetDatabase(databasePath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, err
	}

	statement := `
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		host TEXT NULL,
        username TEXT NULL,
		password TEXT NOT NULL,
		is_admin INTEGER NOT NULL,
		date_created INTEGER NOT NULL,
		date_updated INTEGER NOT NULL
    );
    `
	_, err = db.Exec(statement)
	if err != nil {
		return nil, err
	}

	return db, nil
}

type DatabaseMetadata struct {
	AdminInitialized bool
	PasswordsCount   int
}

func VerifyDatabase(
	database *sql.DB,
) (*DatabaseMetadata, error) {
	var existingCount int

	statement := `
	SELECT COUNT(*) FROM passwords;
	`
	err := database.QueryRow(
		statement,
	).Scan(&existingCount)
	if err != nil {
		return nil, err
	}

	if existingCount <= 0 {
		return &DatabaseMetadata{
			AdminInitialized: false,
			PasswordsCount:   0,
		}, nil
	}

	var adminCount int

	statement = `
	SELECT COUNT(*) FROM passwords WHERE is_admin = ?;
	`
	err = database.QueryRow(
		statement,
		1,
	).Scan(&adminCount)
	if err != nil {
		return nil, err
	}

	if adminCount <= 0 {
		return nil, fmt.Errorf("Invalid database. No admin initialized.")
	}

	if adminCount > 1 {
		return nil, fmt.Errorf("Invalid database. Multiple admins initialized.")
	}

	return &DatabaseMetadata{
		AdminInitialized: true,
		PasswordsCount:   existingCount - 1,
	}, nil
}

func VerifyAdminPassword(
	database *sql.DB,
	adminPassword string,
) error {
	statement := `SELECT password FROM passwords WHERE is_admin = ?;`
	var hashedPassword string

	err := database.QueryRow(statement, 1).Scan(&hashedPassword)
	if err != nil {
		return err
	}

	if !VerifyHashedText(adminPassword, hashedPassword) {
		return fmt.Errorf("Invalid admin password.")
	}

	return nil
}

func SetPassword(
	database *sql.DB,
	adminPassword,
	host,
	username,
	password string,
) error {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return err
	}

	encryptedPassword, err := EncryptText(adminPassword, password)
	if err != nil {
		return err
	}

	currentTime := time.Now().UnixMilli()
	var existingCount int

	statement := `
	SELECT COUNT(*) FROM passwords WHERE host = ? AND username = ? AND is_admin = ?;
	`
	err = database.QueryRow(
		statement,
		host,
		username,
		0,
	).Scan(&existingCount)
	if err != nil {
		return err
	}

	if existingCount <= 0 {
		statement = `INSERT INTO passwords(host, username, password, is_admin, ` +
			`date_created, date_updated) VALUES(?, ?, ?, ?, ?, ?);`
		_, err = database.Exec(
			statement,
			host,
			username,
			encryptedPassword,
			0,
			currentTime,
			currentTime,
		)
		if err != nil {
			return err
		}

	} else {
		statement = `UPDATE passwords SET password = ?, date_updated = ? ` +
			`WHERE host = ? AND username = ? AND is_admin = ?;`
		_, err = database.Exec(
			statement,
			encryptedPassword,
			currentTime,
			host,
			username,
			0,
		)
		if err != nil {
			return err
		}

	}

	return nil
}

type PasswordEntry struct {
	Host        string
	Username    string
	Password    string
	DateCreated time.Time
	DateUpdated time.Time
}

func GetPasswords(
	database *sql.DB,
	adminPassword,
	host string,
) ([]PasswordEntry, error) {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return nil, err
	}

	statement := `SELECT username, password, date_created, date_updated ` +
		`FROM passwords WHERE host = ? AND is_admin = ?;`
	rows, err := database.Query(statement, host, 0)
	if err != nil {
		return nil, err
	}

	var entries []PasswordEntry
	for rows.Next() {
		entry := PasswordEntry{
			Host: host,
		}

		var username string
		var dateCreated int
		var dateUpdated int
		var encryptedPassword string

		rows.Scan(
			&username,
			&encryptedPassword,
			&dateCreated,
			&dateUpdated,
		)

		password, err := DecryptText(adminPassword, encryptedPassword)
		if err != nil {
			return nil, err
		}

		entry.Username = username
		entry.Password = password
		entry.DateCreated = time.UnixMilli(int64(dateCreated))
		entry.DateUpdated = time.UnixMilli(int64(dateUpdated))

		entries = append(entries, entry)
	}

	return entries, nil
}

type HostPasswordCount struct {
	Host          string
	PasswordCount int
}

func GetHosts(
	database *sql.DB,
	adminPassword string,
) ([]HostPasswordCount, error) {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return nil, err
	}

	statement := `
	SELECT
		host,
		COUNT(*) AS password_count
	FROM passwords
	WHERE host IS NOT NULL
	AND host != ''
	AND is_admin = ?
	GROUP BY host
	ORDER BY password_count DESC;
	`
	rows, err := database.Query(statement, 0)
	if err != nil {
		return nil, err
	}

	var entries []HostPasswordCount
	for rows.Next() {
		entry := HostPasswordCount{}

		var host string
		var count int

		rows.Scan(
			&host,
			&count,
		)

		entry.Host = host
		entry.PasswordCount = count

		entries = append(entries, entry)
	}

	return entries, nil
}

func SearchPasswords(
	database *sql.DB,
	adminPassword,
	search string,
) ([]PasswordEntry, error) {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return nil, err
	}

	statement := `SELECT host, username, password, date_created, date_updated ` +
		`FROM passwords WHERE (host LIKE ? OR username LIKE ?) AND is_admin = ?;`
	rows, err := database.Query(
		statement,
		"%"+search+"%",
		"%"+search+"%",
		0,
	)
	if err != nil {
		return nil, err
	}

	var entries []PasswordEntry
	for rows.Next() {
		entry := PasswordEntry{}

		var host string
		var username string
		var dateCreated int
		var dateUpdated int
		var encryptedPassword string

		rows.Scan(
			&host,
			&username,
			&encryptedPassword,
			&dateCreated,
			&dateUpdated,
		)

		password, err := DecryptText(adminPassword, encryptedPassword)
		if err != nil {
			return nil, err
		}

		entry.Host = host
		entry.Username = username
		entry.Password = password
		entry.DateCreated = time.UnixMilli(int64(dateCreated))
		entry.DateUpdated = time.UnixMilli(int64(dateUpdated))

		entries = append(entries, entry)
	}

	return entries, nil
}

func DeletePasswords(
	database *sql.DB,
	adminPassword,
	host string,
) error {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return err
	}

	statement := `DELETE FROM passwords WHERE host = ? AND is_admin = ?;`
	_, err = database.Exec(statement, host, 0)
	if err != nil {
		return err
	}

	return nil
}

func ClearPasswords(
	database *sql.DB,
	adminPassword string,
) error {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return err
	}

	statement := `DELETE FROM passwords WHERE is_admin = ?;`
	_, err = database.Exec(statement, 0)
	if err != nil {
		return err
	}

	return nil
}

func GetPassword(
	database *sql.DB,
	adminPassword,
	host,
	username string,
) (*PasswordEntry, error) {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return nil, err
	}

	statement := `SELECT username, password, date_created, date_updated ` +
		`FROM passwords WHERE host = ? AND username = ? AND is_admin = ?;`

	entry := PasswordEntry{
		Host: host,
	}

	var username_ string
	var dateCreated int
	var dateUpdated int
	var encryptedPassword string

	err = database.QueryRow(statement, host, username, 0).Scan(
		&username_,
		&encryptedPassword,
		&dateCreated,
		&dateUpdated,
	)
	if err != nil {
		return nil, err
	}

	password, err := DecryptText(adminPassword, encryptedPassword)
	if err != nil {
		return nil, err
	}

	entry.Username = username_
	entry.Password = password
	entry.DateCreated = time.UnixMilli(int64(dateCreated))
	entry.DateUpdated = time.UnixMilli(int64(dateUpdated))

	return &entry, nil
}

func DeletePassword(
	database *sql.DB,
	adminPassword,
	host,
	username string,
) error {
	err := VerifyAdminPassword(database, adminPassword)
	if err != nil {
		return err
	}

	statement := `DELETE FROM passwords WHERE host = ? AND username = ? AND is_admin = ?;`
	_, err = database.Exec(statement, host, username, 0)
	if err != nil {
		return err
	}

	return nil
}

func InitializeAdminPassword(
	database *sql.DB,
	adminPassword string,
) error {
	databaseTransaction, err := database.Begin()
	if err != nil {
		return err
	}
	defer databaseTransaction.Rollback()

	statement := `DELETE FROM passwords;`
	_, err = databaseTransaction.Exec(statement, 1)
	if err != nil {
		return err
	}

	hashedPassword, err := HashText(adminPassword)
	if err != nil {
		return err
	}

	currentTime := time.Now().UnixMilli()
	statement = `INSERT INTO passwords(password, is_admin, ` +
		`date_created, date_updated) VALUES(?, ?, ?, ?);`
	_, err = databaseTransaction.Exec(
		statement,
		hashedPassword,
		1,
		currentTime,
		currentTime,
	)
	if err != nil {
		return err
	}

	err = databaseTransaction.Commit()
	if err != nil {
		return err
	}

	return nil
}

func reEncryptPasswords(
	databaseTransaction *sql.Tx,
	currentAdminPassword,
	newAdminPassword string,
) error {
	statement := `SELECT id, password FROM passwords WHERE is_admin = ?;`
	rows, err := databaseTransaction.Query(statement, 0)
	if err != nil {
		return err
	}

	entryUpdates := map[int]string{}

	for rows.Next() {
		var entryId int
		var entryPassword string

		rows.Scan(
			&entryId,
			&entryPassword,
		)

		password, err := DecryptText(currentAdminPassword, entryPassword)
		if err != nil {
			return err
		}

		password, err = EncryptText(newAdminPassword, password)
		if err != nil {
			return err
		}

		entryUpdates[entryId] = password
	}

	currentTime := time.Now().UnixMilli()

	for entryId, entryPassword := range entryUpdates {
		statement := `UPDATE passwords SET password = ?, date_updated = ? ` +
			`WHERE id = ? AND is_admin = ?;`
		_, err = databaseTransaction.Exec(
			statement,
			entryPassword,
			currentTime,
			entryId,
			0,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func SetAdminPassword(
	database *sql.DB,
	currentAdminPassword,
	newAdminPassword string,
) error {
	err := VerifyAdminPassword(database, currentAdminPassword)
	if err != nil {
		return err
	}

	databaseTransaction, err := database.Begin()
	if err != nil {
		return err
	}
	defer databaseTransaction.Rollback()

	err = reEncryptPasswords(
		databaseTransaction,
		currentAdminPassword,
		newAdminPassword,
	)
	if err != nil {
		return err
	}

	statement := `DELETE FROM passwords WHERE is_admin = ?;`
	_, err = databaseTransaction.Exec(statement, 1)
	if err != nil {
		return err
	}

	hashedPassword, err := HashText(newAdminPassword)
	if err != nil {
		return err
	}

	currentTime := time.Now().UnixMilli()
	statement = `INSERT INTO passwords(password, is_admin, ` +
		`date_created, date_updated) VALUES(?, ?, ?, ?);`
	_, err = databaseTransaction.Exec(
		statement,
		hashedPassword,
		1,
		currentTime,
		currentTime,
	)
	if err != nil {
		return err
	}

	err = databaseTransaction.Commit()
	if err != nil {
		return err
	}

	return nil
}
