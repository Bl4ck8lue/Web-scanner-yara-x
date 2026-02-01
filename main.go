package main

import (
	"context"
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
	"time"

	"crypto/md5"

	"github.com/jackc/pgx/v5"
)

var (
	staticDir   = "./static"
	templateDir = "./templates"
	// настройки
	maxUploadSize int64 = 100 << 20 // 100 MiB
	// параллельных сканирований
	concurrency = 4
	sem         = make(chan struct{}, 4)
	// python скрипт (относительный или абсолютный путь) — поправь под своё расположение
	pythonBin   = "python3"
	scriptPath  = "./scripts/analyze.py"
	scriptPath1 = "./scripts/registr.py"
	scriptPath2 = "./scripts/signin.py"
	scanTimeout = 90 * time.Second
)

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	http.HandleFunc("/", home)
	http.HandleFunc("/about", aboutHandler)
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/reg", regHandler)
	http.HandleFunc("/sign", signHandler)

	fmt.Println("Starting server at :8090")
	if err := http.ListenAndServe(":8090", nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Println("server error:", err)
	}
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

func regInDB(name string, email string, pass string) {
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		log.Fatal("Hе удалось подключиться к БД:", err)
	}
	defer conn.Close(context.Background())

	// Выполняем простой SQL-запрос
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

	// Выводим результат
	fmt.Println("Added")
}

func regHandler(w http.ResponseWriter, r *http.Request) {

	// Ограничить размер тела
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("p1")

	regInDB(name, email, password)

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

func signInDB(email string, pass string) {
	//postgres://ilya:4suh12iiyu@localhost:5432/web_scanner
	//postrges://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME
	// Устанавливаем соединение с базой данных
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		log.Fatal("не удалось подключиться к БД:", err)
	}
	defer conn.Close(context.Background())

	// Выполняем простой SQL-запрос
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
	err = conn.QueryRow(context.Background(), "select $1 from reg_users", pass).Scan(&chpass)
	if err != nil {
		log.Fatal(err)
	}

	mdpass := md5.Sum([]byte(pass))
	passmd := hex.EncodeToString(mdpass[:])
	if chpass == passmd {
		fmt.Println("Hello, " + email)
	}

	// Выводим результат
	fmt.Println(greeting)
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	// Ограничить размер тела
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("p1")

	signInDB(email, password)

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

// scanHandler: принимает multipart form field "file", сохраняет временно, вызывает python скрипт,
// ждёт результата и возвращает JSON с { exit_code, output }
func scanHandler(w http.ResponseWriter, r *http.Request) {
	// Ограничить размер тела
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

	// создать temp файл
	tmp, err := os.CreateTemp("", "scan-*-"+filename)
	if err != nil {
		http.Error(w, "internal error creating temp file", http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	// копируем содержимое
	if _, err := io.Copy(tmp, file); err != nil {
		http.Error(w, "failed to save uploaded file", http.StatusInternalServerError)
		return
	}

	// семафор параллелизма
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		http.Error(w, "server busy, try later", http.StatusTooManyRequests)
		return
	}

	// запустить python скрипт с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, scriptPath, tmpPath)
	out, err := cmd.CombinedOutput()

	// timeout?
	if ctx.Err() == context.DeadlineExceeded {
		http.Error(w, "scan timeout", http.StatusGatewayTimeout)
		return
	}

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
	json.NewEncoder(w).Encode(resp)
}
