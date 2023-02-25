package cli

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	"check-pwd/password"
)

func Run() error {
	flags := parseFlags()

	// Check password from cli arg.
	if !*flags.file {
		hash := password.NewHash(flags.passwords)
		_, err := password.CheckPassword(*hash)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("password is not compromised.")
		return nil
	}

	// Check passwords in batch from filepath.
	pwds, err := parseFile(flags.passwords)
	if err != nil {
		log.Fatal(err)
	}
	var compPwd int
	for _, p := range pwds {
		hash := password.NewHash(p)
		bad, err := password.CheckPassword(*hash)
		if err != nil {
			log.Fatal(err)
		}
		if bad {
			compPwd++
		}
	}

	fmt.Printf("%v/%v of your passwords are compromised!", compPwd, len(pwds))

	return nil
}

type flags struct {
	// passwords either contains a single password or a filepath to a file of \n
	// delimited passwords in plain text.
	passwords string

	// file flags whether passwords is a filepath.
	file *bool
}

func parseFlags() flags {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [flags] <passwords>\n", os.Args[0])
		fmt.Println("Either pass a password directly or use a '\\n' delimited file:")
		fmt.Println(" - check-pwd password1")
		fmt.Println(" - check-pwd --file passwords.txt")

		fmt.Println("\nFlags:")
		flag.PrintDefaults()
	}
	file := flag.Bool("file", false, "path to file of passwords")

	flag.Parse()
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(0)
	}
	pwd := flag.Arg(0)

	return flags{passwords: pwd, file: file}
}

// parseFile reads in a file from a path containing '\n' separated strings each
// of which are passwords to allow for batch checking of passwords.
//
// TODO: storing passwords in a plain text file like this is very unsafe.
// Investigate how this could be integrated with apple key chain.
func parseFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var l []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		l = append(l, s.Text())
	}

	return l, s.Err()
}
