package main

import (
	"log"
	"os"

	CORE "github.com/DerrohXy/PKeeper/core"
	_ "github.com/mattn/go-sqlite3"
)

func getCmdArgs() []string {
	if len(os.Args) > 1 {
		return os.Args[1:]
	}

	return []string{}
}

func main() {
	args := getCmdArgs()

	if len(args) < 1 {
		log.Println("No command specified.")

	} else {
		databaseFile, err := CORE.FindDatabaseFile()
		if err != nil {
			databaseFile = CORE.DEFAULT_DATABASE_FILE_NAME
		}

		cmd := args[0]

		switch cmd {
		case "terminal":
			terminal := CORE.Terminal{}
			terminal.Start(databaseFile)

			return

		default:
			log.Printf("Invalid command : %s.\n", cmd)
		}
	}

}
