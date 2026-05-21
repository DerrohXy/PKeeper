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
	IsAuthenticated bool
	AdminPassword   string
	Database        *sql.DB
}

func (instance *Terminal) Start(databasePath string) {
	database, err := GetDatabase(databasePath)
	if err != nil {
		log.Println("Unable to connect to databse.")
		log.Fatal(err)
	}

	defer database.Close()

	instance.Database = database

	databaseMetadata, err := VerifyDatabase(database)
	if err != nil {
		log.Println("Unable to verify databse.")
		log.Fatal(err)
	}

	var adminPassword string

	if !databaseMetadata.AdminInitialized {
		adminPassword = instance.ReadTerminalInput("Set Admin Password :")
		err = InitializeAdminPassword(instance.Database, adminPassword)

		if err != nil {
			log.Println("Unable to setup admin password.")
			log.Fatal(err)
		}

	} else {
		adminPassword = instance.ReadTerminalInput("Enter Admin Password :")
		err = VerifyAdminPassword(instance.Database, adminPassword)

		if err != nil {
			log.Println("Unable to verify admin password.")
			log.Fatal(err)
		}
	}

	instance.AdminPassword = adminPassword

	for {
		command := instance.ReadTerminalInput(">>>")
		instance.ProcessCommand(command)
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

	case "set-admin-password":
		newPassword := instance.ReadTerminalInput("Enter new password :")
		err := SetAdminPassword(
			instance.Database,
			instance.AdminPassword,
			newPassword,
		)

		if err != nil {
			log.Println("Error setting admin password.")
			log.Println(err)
		}

		instance.AdminPassword = newPassword

		return

	case "set-password":
		host := instance.ReadTerminalInput("Enter host :")
		username := instance.ReadTerminalInput("Enter username :")
		password := instance.ReadTerminalInput("Enter password :")
		existingPassword, _ := GetPassword(
			instance.Database,
			instance.AdminPassword,
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
				instance.Database,
				instance.AdminPassword,
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
			instance.Database,
			instance.AdminPassword,
			host,
			username,
			password,
		)

		if err != nil {
			log.Println("Error setting password.")
			log.Println(err)
		}

		return

	case "get-password":
		host := instance.ReadTerminalInput("Enter host :")
		existingPasswords, err := GetPasswords(
			instance.Database,
			instance.AdminPassword,
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

	case "delete-password":
		host := instance.ReadTerminalInput("Enter host :")
		username := instance.ReadTerminalInput("Enter username, or blank for all :")
		if username == "" {
			err := DeletePasswords(
				instance.Database,
				instance.AdminPassword,
				host,
			)

			if err != nil {
				log.Println("Error deleting passwords.")
				log.Println(err)
			}

			return
		}

		err := DeletePassword(
			instance.Database,
			instance.AdminPassword,
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
			instance.Database,
			instance.AdminPassword,
		)

		if err != nil {
			log.Println("Error clearing passwords.")
			log.Println(err)
		}

		return

	default:
		log.Printf("Invalid command : %s\n", command)
	}
}
