package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	staticDir   = "./static"
	templateDir = "./templates"

	maxUploadSize int64 = 100 << 20 // 100 MiB

	concurrency = 4
	sem         = make(chan struct{}, 4)

	rulesPath          = "./rules/"
	scanTimeout        = 90 * time.Second
	archiveScanTimeout = 10 * time.Minute // отдельный таймаут для архивов
)

var archiveSem chan struct{}

func main() {
	workers := runtime.GOMAXPROCS(0) - 1
	if workers < 1 {
		workers = 1
	}
	archiveSem = make(chan struct{}, workers)
	log.Printf("archive scan workers: %d", workers)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	http.HandleFunc("/", home)
	http.HandleFunc("/about", aboutHandler)
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/reg", regHandler)
	http.HandleFunc("/sign", signHandler)
	http.HandleFunc("/api/check-auth", checkAuthHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/loadingRules", loadingHandler)
	http.HandleFunc("/chooseRules", choosingHandler)
	http.HandleFunc("/api/list-rules", listRulesHandler)
	http.HandleFunc("/road", roadHandler)
	http.HandleFunc("/history", histHandler)
	http.HandleFunc("/api/scanfiles", scanfilesHandler)

	fmt.Println("Starting server at :8025")
	if err := http.ListenAndServe(":8025", nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Println("server error:", err)
	}
}

func scanfilesHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	const dateFmt = "2006-01-02"
	var fromTime, toTime time.Time
	hasFrom, hasTo := false, false

	if fs := r.URL.Query().Get("from"); fs != "" {
		if t, err := time.Parse(dateFmt, fs); err == nil {
			fromTime = t
			hasFrom = true
		}
	}
	if ts := r.URL.Query().Get("to"); ts != "" {
		if t, err := time.Parse(dateFmt, ts); err == nil {
			// включаем весь день «to» — берём конец суток
			toTime = t.Add(24*time.Hour - time.Second)
			hasTo = true
		}
	}

	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		http.Error(w, "db connection error", http.StatusInternalServerError)
		return
	}
	defer conn.Close(context.Background())

	var (
		query string
		args  []any
	)
	switch {
	case hasFrom && hasTo:
		query = "SELECT id, email, filename, size, date, threats_count, COALESCE(threats_list,'') FROM scanfiles WHERE email = $1 AND date >= $2 AND date <= $3 ORDER BY date DESC"
		args = []any{c.Value, fromTime, toTime}
	case hasFrom:
		query = "SELECT id, email, filename, size, date, threats_count, COALESCE(threats_list,'') FROM scanfiles WHERE email = $1 AND date >= $2 ORDER BY date DESC"
		args = []any{c.Value, fromTime}
	case hasTo:
		query = "SELECT id, email, filename, size, date, threats_count, COALESCE(threats_list,'') FROM scanfiles WHERE email = $1 AND date <= $2 ORDER BY date DESC"
		args = []any{c.Value, toTime}
	default:
		query = "SELECT id, email, filename, size, date, threats_count, COALESCE(threats_list,'') FROM scanfiles WHERE email = $1 ORDER BY date DESC"
		args = []any{c.Value}
	}

	rows, err := conn.Query(context.Background(), query, args...)
	if err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var id, filename, size, threats_count, threatsList string
		var date time.Time

		if err := rows.Scan(&id, &c.Value, &filename, &size, &date, &threats_count, &threatsList); err != nil {
			http.Error(w, "scan error", http.StatusInternalServerError)
			return
		}

		// Разбиваем строку угроз обратно в слайс для передачи фронтенду
		var threatNames []string
		if threatsList != "" {
			for _, t := range strings.Split(threatsList, "|") {
				if t != "" {
					threatNames = append(threatNames, t)
				}
			}
		}

		results = append(results, map[string]any{
			"filename":      filename,
			"size":          size,
			"date":          date.Format("02-01-2006"),
			"threats_count": threats_count,
			"threats_list":  threatNames,
		})
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "rows error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func histHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		fmt.Println("Error")
	}
	if c.Value != "" {
		path := filepath.Join(templateDir, "indexHistory.html")
		tmpl, err := template.ParseFiles(path)

		if err != nil {
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		fmt.Println("No one auth!")
	}
}

func roadHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		fmt.Println("Error")
	}
	if c.Value == "admin@admin.ru" {
		path := filepath.Join(templateDir, "indexChoose.html")
		tmpl, err := template.ParseFiles(path)

		if err != nil {
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

const rulesDir = "./rules"

func listRulesHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("email"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		http.Error(w, "cannot read directory", http.StatusInternalServerError)
		return
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func choosingHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		fmt.Println("Error")
	}
	if c.Value == "admin@admin.ru" {
		path := filepath.Join(templateDir, "indexRules.html")
		tmpl, err := template.ParseFiles(path)

		if err != nil {
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

const uploadDir = "./scripts"

func loadingHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)

	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "internal error: cannot create upload directory", http.StatusInternalServerError)
		return
	}

	tmp, err := os.Create("./rules/" + filename)
	if err != nil {
		http.Error(w, "internal error creating file", http.StatusInternalServerError)
		return
	}

	defer tmp.Close()

	if _, err := io.Copy(tmp, file); err != nil {
		http.Error(w, "failed to save uploaded file", http.StatusInternalServerError)
		return
	}

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		http.Error(w, "server busy, try later", http.StatusTooManyRequests)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("file uploaded successfully"))
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		fmt.Println("Error")
	}
	if c.Value == "admin@admin.ru" {
		path := filepath.Join(templateDir, "indexAd.html")
		tmpl, err := template.ParseFiles(path)

		if err != nil {
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func checkAuthHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		resp := map[string]any{
			"authenticated": false,
			"email":         "",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := map[string]any{
		"authenticated": true,
		"email":         c.Value,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func home(w http.ResponseWriter, r *http.Request) {

	path := filepath.Join(templateDir, "index.html")
	tmpl, err := template.ParseFiles(path)

	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
		return
	}

}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "This is the about page.")
}

func regInDB(name string, email string, pass string) int {
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		log.Fatal("Hе удалось подключиться к БД:", err)
	}
	defer conn.Close(context.Background())

	var greeting string
	err = conn.QueryRow(context.Background(), "select count(*) from reg_users where email = $1", email).Scan(&greeting)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(greeting)

	if greeting != "0" {
		log.Fatal("Error! Exists")
	}

	_, err = conn.Exec(context.Background(), "insert into reg_users (name, email, pass) values ($1, $2, md5($3))", name, email, pass)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Added")
	return 1
}

func regHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("p1")

	checkReg := regInDB(name, email, password)

	if checkReg == 1 {
		resp := map[string]any{
			"exit_code": "200",
			"output":    "You have just registered!\nPlease log in to the website.",
		}
		//fmt.Println(string(out))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}

	/*
		// запустить python скрипт с таймаутом
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, pythonBin, scriptPath1, name, email, password)
		out, err := cmd.CombinedOutput()

		// timeout?
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "scan timeout", http.StatusGatewayTimeout)
			return
		}
		fmt.Printf("registr output:\n%s\n", string(out))

		// подготовить код возврата
		exitCode := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				exitCode = ee.ExitCode()
			} else {
				http.Error(w, "failed to run scanner: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Формируем ответ — возвращаем stdout (ожидаем JSON от скрипта)
		resp := map[string]any{
			"exit_code": exitCode,
			"output":    string(out),
		}
		//fmt.Println(string(out))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)*/
}

func setCookieDB(email string, w http.ResponseWriter, r *http.Request) {
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		log.Printf("Не удалось подключиться к БД: %v", err)
		return
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(context.Background(),
		"DELETE FROM cookie WHERE email = $1",
		email)
	if err != nil {
		log.Printf("Ошибка удаления старых сессий: %v", err)
	}

	cookie := http.Cookie{
		Name:     "email",
		Value:    email,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)

	_, err = conn.Exec(context.Background(),
		"INSERT INTO cookie (email, value, maxage) VALUES ($1, $2, $3)",
		email, email, 3600)
	if err != nil {
		log.Printf("Ошибка сохранения cookie в БД: %v", err)
	}
}

func signInDB(email string, pass string, w http.ResponseWriter, r *http.Request) int {
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		log.Fatal("не удалось подключиться к БД:", err)
	}
	defer conn.Close(context.Background())

	var greeting string
	err = conn.QueryRow(context.Background(), "select count(*) from reg_users where email = $1", email).Scan(&greeting)
	if err != nil {
		log.Fatal(err)
	}

	if greeting == "0" {
		fmt.Println("Have to reg!")
		log.Fatal("REG!")
	}

	var chpass string
	err = conn.QueryRow(context.Background(), "select pass from reg_users where email = $1", email).Scan(&chpass)
	if err != nil {
		log.Fatal(err)
	}

	res := 1
	mdpass := md5.Sum([]byte(pass))
	passmd := hex.EncodeToString(mdpass[:])

	fmt.Println(passmd)
	fmt.Println(chpass)

	if chpass == passmd {
		fmt.Println("Hello, " + email)
		setCookieDB(email, w, r)
	} else {
		return 225
	}

	fmt.Println(greeting)
	return res
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("p1")

	zxc := signInDB(email, password, w, r)

	resp := map[string]any{
		"exit_code": "200",
		"output":    zxc,
	}
	//fmt.Println(string(out))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	/*
		// запустить python скрипт с таймаутом
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, pythonBin, scriptPath2, email, password)
		out, err := cmd.CombinedOutput()

		fmt.Printf("sign in output:\n%s\n", string(out))

		// подготовить код возврата
		exitCode := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				exitCode = ee.ExitCode()
			} else {
				http.Error(w, "failed to run scanner: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		// Формируем ответ — возвращаем stdout (ожидаем JSON от скрипта)
		resp := map[string]any{
			"exit_code": exitCode,
			"output":    string(out),
		}
		//fmt.Println(string(out))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)*/
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "email",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	deleteCookieFromDB(r)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out successfully"))
}

func deleteCookieFromDB(r *http.Request) {
	if cookie, err := r.Cookie("email"); err == nil {
		conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
		if err != nil {
			log.Printf("Ошибка подключения к БД при выходе: %v", err)
			return
		}
		defer conn.Close(context.Background())

		_, err = conn.Exec(context.Background(),
			"UPDATE cookie SET maxage = -1 WHERE email = $1",
			cookie.Value)
		if err != nil {
			log.Printf("Ошибка обновления cookie в БД: %v", err)
		}
	}
}

func addScanFiles(email string, filename string, size string, date string, threats int, threatsList string) {
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		log.Fatal("Hе удалось подключиться к БД:", err)
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(context.Background(),
		"insert into scanfiles (email, filename, size, date, threats_count, threats_list) values ($1, $2, $3, $4, $5, $6)",
		email, filename, size, date, threats, threatsList)
	if err != nil {
		log.Fatal(err)
	}
}

type ScanResult struct {
	File    string   // имя файла
	Threats []string // список правил
}

type yaraScanOutput struct {
	Matches []struct {
		Rule string `json:"rule"`
	} `json:"matches"`
}

func runYaraScan(ctx context.Context, rulesFile, targetPath string) ([]string, error) {
	outFile := targetPath + ".yara_out.json"
	defer os.Remove(outFile)

	// yr scan --disable-warnings --output-format json <rules> <target> > <out> from analyze.py
	cmd := exec.CommandContext(ctx,
		"./scripts/yr", "scan",
		"--disable-warnings",
		"--output-format", "json",
		rulesFile, targetPath,
	)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard

	_ = cmd.Run()

	if buf.Len() == 0 {
		return nil, nil
	}

	var result yaraScanOutput
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("yr output parse error: %w", err)
	}

	threats := make([]string, 0, len(result.Matches))
	for _, m := range result.Matches {
		if m.Rule != "" {
			threats = append(threats, m.Rule)
		}
	}
	return threats, nil
}

func scanFileBytes(ctx context.Context, rulesFile, name string, data []byte) (ScanResult, error) {
	tmp, err := os.CreateTemp("", "yara-scan-*-"+filepath.Base(name))
	if err != nil {
		return ScanResult{File: name}, fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return ScanResult{File: name}, fmt.Errorf("cannot write temp file: %w", err)
	}
	tmp.Close()

	threats, err := runYaraScan(ctx, rulesFile, tmpPath)
	return ScanResult{File: name, Threats: threats}, err
}

type archiveEntry struct {
	name string
	data []byte
}

func scanArchive(ctx context.Context, rulesFile string, archiveData []byte) ([]ScanResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if err != nil {
		return nil, fmt.Errorf("cannot open zip: %w", err)
	}

	var entries []archiveEntry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			entries = append(entries, archiveEntry{name: f.Name, data: nil})
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			entries = append(entries, archiveEntry{name: f.Name, data: nil})
			continue
		}
		entries = append(entries, archiveEntry{name: f.Name, data: data})
	}

	results := make([]ScanResult, len(entries))

	type job struct{ idx int }
	jobs := make(chan job, len(entries))
	for i := range entries {
		jobs <- job{i}
	}
	close(jobs)

	var wg sync.WaitGroup
	for j := range jobs {
		j := j
		e := entries[j.idx]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.data == nil {
				results[j.idx] = ScanResult{File: e.name}
				return
			}
			select {
			case archiveSem <- struct{}{}:
				defer func() { <-archiveSem }()
			case <-ctx.Done():
				results[j.idx] = ScanResult{File: e.name}
				return
			}
			res, err := scanFileBytes(ctx, rulesFile, e.name, e.data)
			if err != nil {
				log.Printf("scan error for %s: %v", e.name, err)
			}
			results[j.idx] = res
		}()
	}
	wg.Wait()

	return results, nil
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	rulesPath = "./rules/"
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	rules := r.FormValue("rules")
	size := r.FormValue("size")

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "failed to read uploaded file", http.StatusInternalServerError)
		return
	}

	rawHash := md5.Sum(fileBytes)
	fileHash := hex.EncodeToString(rawHash[:])

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		http.Error(w, "server busy, try later", http.StatusTooManyRequests)
		return
	}

	isZip := strings.HasSuffix(strings.ToLower(filename), ".zip")
	timeout := scanTimeout
	if isZip {
		timeout = archiveScanTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fullRulesPath := rulesPath + rules

	var scanResults []ScanResult

	if isZip {
		archiveResults, err := scanArchive(ctx, fullRulesPath, fileBytes)
		if err != nil {
			http.Error(w, "archive scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		scanResults = archiveResults
	} else {
		tmp, err := os.Create(filename)
		if err != nil {
			http.Error(w, "internal error creating temp file", http.StatusInternalServerError)
			return
		}
		defer tmp.Close()

		if _, err := tmp.Write(fileBytes); err != nil {
			http.Error(w, "failed to save uploaded file", http.StatusInternalServerError)
			return
		}
		tmp.Close()

		res, err := runYaraScan(ctx, fullRulesPath, filename)
		if err != nil {
			log.Printf("yara scan error: %v", err)
		}
		scanResults = []ScanResult{{File: filename, Threats: res}}
	}

	if ctx.Err() == context.DeadlineExceeded {
		http.Error(w, "scan timeout", http.StatusGatewayTimeout)
		return
	}

	threatsCount := 0
	for _, r := range scanResults {
		threatsCount += len(r.Threats)
	}
	fmt.Printf("Threats found: %d across %d file(s)\n", threatsCount, len(scanResults))

	var outputLines []string
	outputLines = append(outputLines, "Check:")
	for _, sr := range scanResults {
		for _, threat := range sr.Threats {
			if isZip {
				outputLines = append(outputLines, threat+" ("+sr.File+")")
			} else {
				outputLines = append(outputLines, threat)
			}
		}
	}
	outputStr := strings.Join(outputLines, "\n")

	var threatNames []string
	for _, sr := range scanResults {
		for _, threat := range sr.Threats {
			if isZip {
				threatNames = append(threatNames, threat+" ("+sr.File+")")
			} else {
				threatNames = append(threatNames, threat)
			}
		}
	}
	threatsList := strings.Join(threatNames, "|")

	currentTime := time.Now()
	c, err := r.Cookie("email")
	if err == nil {
		addScanFiles(c.Value, filename, size, currentTime.Format("01-02-2006"), threatsCount, threatsList)
	}

	resp := map[string]any{
		"exit_code":     0,
		"output":        outputStr,
		"hash":          fileHash,
		"threats_count": threatsCount,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
