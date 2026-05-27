package core

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
)

type Terminal struct {
	IsAuthenticated      bool
	DefaultAdminPassword string
	CurrentAdminPassword string
	DefaultDatabase      *sql.DB
	DefaultDatabasePath  string
	CurrentDatabase      *sql.DB
	History              []string
}

func (instance *Terminal) Start(databasePath string) {
	database, err := GetDatabase(databasePath)
	if err != nil {
		log.Println("Unable to connect to databse.")
		log.Fatal(err)
	}

	defer database.Close()

	log.Printf("Using database at %s\n", databasePath)

	instance.DefaultDatabase = database
	instance.DefaultDatabasePath = databasePath
	instance.CurrentDatabase = database

	databaseMetadata, err := VerifyDatabase(database)
	if err != nil {
		log.Println("Unable to verify databse.")
		log.Fatal(err)
	}

	var adminPassword string

	if !databaseMetadata.AdminInitialized {
		adminPassword = instance.ReadTerminalInput("Set Admin Password :")
		err = InitializeAdminPassword(instance.CurrentDatabase, adminPassword)

		if err != nil {
			log.Println("Unable to setup admin password.")
			log.Fatal(err)
		}

	} else {
		adminPassword = instance.ReadTerminalInput("Enter Admin Password :")
		err = VerifyAdminPassword(instance.CurrentDatabase, adminPassword)

		if err != nil {
			log.Println("Unable to verify admin password.")
			log.Fatal(err)
		}
	}

	instance.CurrentAdminPassword = adminPassword
	instance.DefaultAdminPassword = adminPassword

	for {
		command := instance.ReadTerminalInput(">>>")
		instance.ProcessCommand(command)

		instance.History = append(instance.History, command)
	}
}

func (instance *Terminal) ReadTerminalInput(prompt string) string {
	fmt.Print(prompt)
	terminalReader := bufio.NewReader(os.Stdin)
	text, err := terminalReader.ReadString('\n')

	if err != nil {
		return ""
	}

	return strings.Trim(text, "\n ")
}

func (instance *Terminal) ProcessCommand(command string) {
	switch command {
	case "quit":
		os.Exit(0)

	case "exit":
		os.Exit(0)

	case "set-admin-password":
		newPassword := instance.ReadTerminalInput("Enter new password :")
		err := SetAdminPassword(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
			newPassword,
		)

		if err != nil {
			log.Println("Error setting admin password.")
			log.Println(err)
		}

		instance.CurrentAdminPassword = newPassword

		return

	case "set-password":
		host := instance.ReadTerminalInput("Enter host :")
		username := instance.ReadTerminalInput("Enter username :")
		password := instance.ReadTerminalInput("Enter password :")
		existingPassword, _ := GetPassword(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
			host,
			username,
		)

		if existingPassword != nil {
			updateConfirmation := instance.ReadTerminalInput(
				fmt.Sprintf(
					"Update password for %s for %s [%s] (y/n)",
					existingPassword.Username,
					existingPassword.Host,
					existingPassword.Password,
				),
			)
			if updateConfirmation != "y" {
				return
			}

			err := SetPassword(
				instance.CurrentDatabase,
				instance.CurrentAdminPassword,
				host,
				username,
				password,
			)

			if err != nil {
				log.Println("Error updating password.")
				log.Println(err)
			}

			return
		}

		err := SetPassword(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
			host,
			username,
			password,
		)

		if err != nil {
			log.Println("Error setting password.")
			log.Println(err)
		}

		return

	case "get-hosts":
		existingHosts, err := GetHosts(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
		)

		if err != nil {
			log.Println("Error fetching passwords.")
			log.Println(err)

			return
		}

		if len(existingHosts) < 1 {
			log.Println("You have no saved passwords.")

			return
		}

		separator := "-------------------------------------"

		for i := 0; i < len(existingHosts); i += 1 {
			entry := existingHosts[i]
			fmt.Printf(
				"%s\nSite :%s\nPasswords :%d\n%s\n",
				separator,
				entry.Host,
				entry.PasswordCount,
				separator,
			)
		}

		return

	case "get-password":
		host := instance.ReadTerminalInput("Enter host :")
		existingPasswords, err := GetPasswords(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
			host,
		)

		if err != nil {
			log.Println("Error fetching passwords.")
			log.Println(err)

			return
		}

		if len(existingPasswords) < 1 {
			log.Printf("You have no saved passwords for %s.\n", host)

			return
		}

		separator := "-------------------------------------"

		for i := 0; i < len(existingPasswords); i += 1 {
			entry := existingPasswords[i]
			fmt.Printf(
				"%s\nSite :%s\nUsername :%s\nPassword :%s\n%s\n",
				separator,
				entry.Host,
				entry.Username,
				entry.Password,
				separator,
			)
		}

		return

	case "search-password":
		search := instance.ReadTerminalInput("Enter search term :")
		existingPasswords, err := SearchPasswords(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
			search,
		)

		if err != nil {
			log.Println("Error searching passwords.")
			log.Println(err)

			return
		}

		if len(existingPasswords) < 1 {
			log.Printf("No passwords matched your search for %s.\n", search)

			return
		}

		separator := "-------------------------------------"

		for i := 0; i < len(existingPasswords); i += 1 {
			entry := existingPasswords[i]
			fmt.Printf(
				"%s\nSite :%s\nUsername :%s\nPassword :%s\n%s\n",
				separator,
				entry.Host,
				entry.Username,
				entry.Password,
				separator,
			)
		}

		return

	case "delete-password":
		host := instance.ReadTerminalInput("Enter host :")
		username := instance.ReadTerminalInput("Enter username, or blank for all :")
		if username == "" {
			err := DeletePasswords(
				instance.CurrentDatabase,
				instance.CurrentAdminPassword,
				host,
			)

			if err != nil {
				log.Println("Error deleting passwords.")
				log.Println(err)
			}

			return
		}

		err := DeletePassword(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
			host,
			username,
		)

		if err != nil {
			log.Println("Error deleting password.")
			log.Println(err)
		}

		return

	case "clear-passwords":
		clearConfirmation := instance.ReadTerminalInput(
			"Confirm to delete all saved passwords (y/n) :",
		)
		if clearConfirmation != "y" {
			return
		}

		err := ClearPasswords(
			instance.CurrentDatabase,
			instance.CurrentAdminPassword,
		)

		if err != nil {
			log.Println("Error clearing passwords.")
			log.Println(err)
		}

		return

	case "use-database":
		databasePath := instance.ReadTerminalInput("Enter path to database file :")
		database, err := GetDatabase(databasePath)
		if err != nil {
			log.Println("Unable to connect to databse.")

			return
		}

		databaseMetadata, err := VerifyDatabase(database)
		if err != nil {
			log.Println("Unable to verify databse.")

			return
		}

		var adminPassword string

		if !databaseMetadata.AdminInitialized {
			adminPassword = instance.ReadTerminalInput("Set Admin Password :")
			err = InitializeAdminPassword(instance.CurrentDatabase, adminPassword)

			if err != nil {
				log.Println("Unable to setup admin password.")

				return
			}

		} else {
			adminPassword = instance.ReadTerminalInput("Enter Admin Password :")
			err = VerifyAdminPassword(instance.CurrentDatabase, adminPassword)

			if err != nil {
				log.Println("Unable to verify admin password.")

				return
			}
		}

		instance.CurrentDatabase = database
		instance.CurrentAdminPassword = adminPassword

		log.Printf("Using database at %s\n", databasePath)

		return

	case "use-default-database":
		instance.CurrentDatabase = instance.DefaultDatabase
		instance.CurrentAdminPassword = instance.DefaultAdminPassword

		log.Printf("Reverted to database at %s\n", instance.DefaultDatabasePath)

		return

	default:
		log.Printf("Invalid command : %s\n", command)
	}
}
