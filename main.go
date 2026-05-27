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
	defaultDatabaseFile, err := CORE.InitializeDefaultDatabase()
	if err != nil {
		log.Println("Unable to setup default database.")
		log.Fatalln(err)
	}

	args := getCmdArgs()

	if len(args) < 1 {
		log.Println("No command specified.")

	} else {
		cmd := args[0]

		switch cmd {
		case "terminal":
			terminal := CORE.Terminal{}
			terminal.Start(defaultDatabaseFile)

			return

		default:
			log.Printf("Invalid command : %s.\n", cmd)
		}
	}

}
