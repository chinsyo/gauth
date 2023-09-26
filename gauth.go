package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	args := os.Args
	if len(args) <= 1 {
		fmt.Println("usage: gauth <operation> [...]")
		fmt.Println("operations:")
		fmt.Println("    gauth {-c --create} [user] [domain]")
		fmt.Println("    gauth {-v --verify} secret code")
		fmt.Println("    gauth {-d --display} secret")
		fmt.Println("    gauth {-l --list} filename [--continue]")
		return
	}

	cmd := args[1]
	switch cmd {
	case "-c", "--create":
		key := generateSecretKey()
		fmt.Println("secret:", key)
		user := ""
		domain := ""
		if len(args) > 2 {
			user = args[2]
		}
		if len(args) > 3 {
			domain = args[3]
		}
		otpAuthURL := getOTPAuthURL(user, domain, key)
		fmt.Println("url:", otpAuthURL)
		barcodeURL := getBarcodeURL(user, domain, key)
		fmt.Println("barcode:", barcodeURL)

	case "-v", "--verify":
		if len(args) < 4 {
			fmt.Println("require secret and code parameters")
			return
		}
		secret := args[2]
		code := args[3]
		if verifyTimeBased(secret, code, 3) == -1 {
			fmt.Println("verification failed")
			return
		}
		fmt.Println("verification succeeded")

	case "-d", "--display":
		if len(args) < 3 {
			fmt.Println("require secret parameter")
			return
		}
		secret := args[2]
		code := generateCode(secret, nil)
		fmt.Println(code)

	case "-l", "--list":
		if len(args) < 3 {
			fmt.Println("require file name")
			return
		}
		filename := args[2]
		if strings.Contains(filename, "~") {
			homeDir, _ := os.UserHomeDir()
			filename = strings.Replace(filename, "~", homeDir, 1)
		}
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			fmt.Printf("can not read: %s\n", filename)
			return
		}
		cont := false
		if len(args) >= 4 {
			if args[3] == "-" || args[3] == "-c" || args[3] == "--continue" {
				cont = true
			}
		}
		config := loadINI(filename)
		keys := make([]string, 0, len(config))
		for key := range config {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		table := make([][]string, 0)
		for _, key := range keys {
			cfg := config[key]
			if cfg == nil {
				continue
			}
			secret := cfg["secret"]
			user := cfg["user"]
			domain := cfg["domain"]
			table = append(table, []string{secret, user, domain})
		}
		listCode(table, cont)

	default:
		fmt.Println("unknown operation")
	}
}

func generateSecretKey() string {
	const length = 16
	byteHash := generateRandomBytes()
	if length > 102 {
		byteRand := generateRandomBytes()
		byteHash = append(byteHash, byteRand...)
	}
	text := base32.StdEncoding.EncodeToString(byteHash)[:length]
	return text
}

func generateRandomBytes() []byte {
	shaHash := sha512.New()
	shaHash.Write(make([]byte, 8192))
	byteHash := shaHash.Sum(nil)

	for i := 0; i < 6; i++ {
		shaHash = sha512.New()
		shaHash.Write(byteHash)
		byteHash = shaHash.Sum(nil)
	}

	return byteHash
}

func getOTPAuthURL(user, domain, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s@%s?secret=%s", user, domain, secret)
}

func getBarcodeURL(user, domain, secret string) string {
	optURL := getOTPAuthURL(user, domain, secret)
	url := "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=" + optURL
	return url
}

func generateCode(secret string, value []byte) string {
	if value == nil {
		value = make([]byte, 8)
		binary.BigEndian.PutUint64(value, uint64(time.Now().Unix()/30))
	}

	token := strings.ReplaceAll(secret, " ", "")
	decodedSecret, _ := base32.StdEncoding.DecodeString(token)

	hash := hmac.New(sha1.New, decodedSecret)
	hash.Write(value)
	hashResult := hash.Sum(nil)

	offset := int(hashResult[len(hashResult)-1]) & 0xf
	truncatedHash := hashResult[offset : offset+4]

	truncatedHashInt := binary.BigEndian.Uint32(truncatedHash)
	truncatedHashInt &= 0x7fffffff
	truncatedHashInt %= 1000000

	return fmt.Sprintf("%06d", truncatedHashInt)
}

func verifyCounterBased(secret, code string, counter int, window int) int {
	for offset := 1; offset <= window; offset++ {
		value := make([]byte, 8)
		binary.BigEndian.PutUint64(value, uint64(counter+offset))
		validCode := generateCode(secret, value)
		if code == validCode {
			return counter + offset
		}
	}
	return -1
}

func verifyTimeBased(secret, code string, window int) int {
	epoch := time.Now().Unix() / 30

	for offset := -(window / 2); offset < window-(window/2); offset++ {
		value := make([]byte, 8)
		binary.BigEndian.PutUint64(value, uint64(epoch)+uint64(offset))
		validCode := generateCode(secret, value)
		if code == validCode {
			return int(epoch) + offset
		}
	}

	return -1
}

func loadINI(filename string) map[string]map[string]string {
	config := make(map[string]map[string]string)

	content, err := os.ReadFile(filename)
	if err != nil {
		return config
	}

	text := string(content)
	lines := strings.Split(text, "\n")
	var section string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if len(line) == 0 {
			continue
		}

		if line[0] == '[' && line[len(line)-1] == ']' {
			section = line[1 : len(line)-1]
			config[section] = make(map[string]string)
		} else {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				config[section][key] = value
			}
		}
	}

	return config
}

func listCode(table [][]string, cont bool) int {
	for {
		current := int(time.Now().Unix())
		epoch := current / 30
		life := 30 - (current % 30)
		rows := [][]string{{"User", "Domain", "Code", "Life Time"}}
		for _, record := range table {
			secret := record[0]
			user := record[1]
			domain := record[2]
			value := make([]byte, 8)
			binary.BigEndian.PutUint64(value, uint64(epoch))
			code := generateCode(secret, value)
			rows = append(rows, []string{user, domain, code, fmt.Sprintf("  %d (s)", life)})
		}

		var style string
		if env, ok := os.LookupEnv("GOOGAUTH_STYLE"); ok {
			style = env
		} else {
			style = "2"
		}
		fmt.Println(tabulify(rows, style))
		if !cont {
			break
		}
		fmt.Println("press Ctrl+C to break ...")
		time.Sleep(1 * time.Second)
	}
	return 0
}

func tabulify(rows [][]string, style string) string {
	colsize := make(map[int]int)
	maxcol := 0
	output := []string{}
	if len(rows) == 0 {
		return ""
	}
	for _, row := range rows {
		maxcol = max(maxcol, len(row))
		for col, text := range row {
			text := text
			size := len(text)
			if _, ok := colsize[col]; !ok {
				colsize[col] = size
			} else {
				colsize[col] = max(size, colsize[col])
			}
		}
	}
	if maxcol <= 0 {
		return ""
	}

	for y, _ := range rows {
		line := ""
		for x := 0; x < maxcol; x++ {
			csize := colsize[x]
			if y >= len(rows) {
				line += strings.Repeat(" ", csize+2)
			} else {
				row := rows[y]
				if x >= len(row) {
					line += strings.Repeat(" ", csize+2)
				} else {
					text := row[x]
					padding := 2 + csize - len(text)
					pad1 := 1
					pad2 := padding - pad1
					line += strings.Repeat(" ", pad1) + text + strings.Repeat(" ", pad2)
				}
			}
		}
		output = append(output, line)
	}

	if style == "0" {
		return strings.Join(output, "\n")
	} else if style == "1" {
		newrows := make([][]string, 0)
		if len(rows) > 0 {
			newrows = append(newrows, rows[:1]...)
			head := []string{}
			for i := 0; i < maxcol; i++ {
				head = append(head, strings.Repeat("-", colsize[i]))
			}
			newrows = append(newrows, head)
			newrows = append(newrows, rows[1:]...)
		}
		output = []string{}
		for y, _ := range newrows {
			line := ""
			for x := 0; x < maxcol; x++ {
				csize := colsize[x]
				if y >= len(newrows) {
					line += strings.Repeat(" ", csize+2)
				} else {
					row := newrows[y]
					if x >= len(row) {
						line += strings.Repeat(" ", csize+2)
					} else {
						text := row[x]
						padding := 2 + csize - len(text)
						pad1 := 1
						pad2 := padding - pad1
						line += strings.Repeat(" ", pad1) + text + strings.Repeat(" ", pad2)
					}
				}
			}
			output = append(output, line)
		}
		return strings.Join(output, "\n")
	} else if style == "2" {
		sep := "+"
		for x := 0; x < maxcol; x++ {
			sep += strings.Repeat("-", colsize[x]+2) + "+"
		}
		output = append(output, sep)
		for y, _ := range rows {
			line := "|"
			for x := 0; x < maxcol; x++ {
				csize := colsize[x]
				if y >= len(rows) {
					line += strings.Repeat(" ", csize+2) + "|"
				} else {
					row := rows[y]
					if x >= len(row) {
						line += strings.Repeat(" ", csize+2) + "|"
					} else {
						text := row[x]
						padding := 2 + csize - len(text)
						pad1 := 1
						pad2 := padding - pad1
						line += strings.Repeat(" ", pad1) + text + strings.Repeat(" ", pad2) + "|"
					}
				}
			}
			output = append(output, line)
			output = append(output, sep)
		}
		return strings.Join(output, "\n")
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
