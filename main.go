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
	rulesPath   = "./rules/"
	buffName    = ""
	scanTimeout = 90 * time.Second
)

func main() {
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

	fmt.Println("Starting server at :8085")
	if err := http.ListenAndServe(":8085", nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Println("server error:", err)
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

const uploadDir = "./scripts" // целевая директория для сохранения файлов
func loadingHandler(w http.ResponseWriter, r *http.Request) {
	// Ограничить размер тела запроса
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

	// Безопасное имя файла (только базовая часть)
	filename := filepath.Base(header.Filename)

	// Убедимся, что целевая директория существует
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "internal error: cannot create upload directory", http.StatusInternalServerError)
		return
	}

	// Создаём временный файл в нужной папке с уникальным именем
	// Шаблон "scan-*-" + оригинальное имя файла (без пути)
	tmp, err := os.Create("./rules/" + filename)
	if err != nil {
		http.Error(w, "internal error creating file", http.StatusInternalServerError)
		return
	}

	// Закрываем файл при выходе, но НЕ удаляем (файл остаётся в uploadDir)
	defer tmp.Close()

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
	// Здесь можно добавить дальнейшую обработку файла (например, антивирусная проверка)
	// ...

	// Успешный ответ
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
	return 1
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

	// Удаляем старые сессии для этого пользователя
	_, err = conn.Exec(context.Background(),
		"DELETE FROM cookie WHERE email = $1",
		email)
	if err != nil {
		log.Printf("Ошибка удаления старых сессий: %v", err)
	}

	// Создаем новую сессию
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

	// Сохраняем в БД
	_, err = conn.Exec(context.Background(),
		"INSERT INTO cookie (email, value, maxage) VALUES ($1, $2, $3)",
		email, email, 3600)
	if err != nil {
		log.Printf("Ошибка сохранения cookie в БД: %v", err)
	}
}

func signInDB(email string, pass string, w http.ResponseWriter, r *http.Request) int {
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

	// Выводим результат
	fmt.Println(greeting)
	return res
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

// Добавьте новый обработчик для выхода
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Удаляем куку, устанавливая MaxAge в -1
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

	// Также можно удалить запись из БД, если это необходимо
	deleteCookieFromDB(r)

	// Возвращаем успешный статус
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out successfully"))
}

// Функция для удаления куки из БД (опционально)
func deleteCookieFromDB(r *http.Request) {
	// Получаем email из куки перед удалением
	if cookie, err := r.Cookie("email"); err == nil {
		conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
		if err != nil {
			log.Printf("Ошибка подключения к БД при выходе: %v", err)
			return
		}
		defer conn.Close(context.Background())

		// Удаляем запись из таблицы cookie или устанавливаем maxage = -1
		_, err = conn.Exec(context.Background(),
			"UPDATE cookie SET maxage = -1 WHERE email = $1",
			cookie.Value)
		if err != nil {
			log.Printf("Ошибка обновления cookie в БД: %v", err)
		}
	}
}

// scanHandler: принимает multipart form field "file", сохраняет временно, вызывает python скрипт,
// ждёт результата и возвращает JSON с { exit_code, output }
func scanHandler(w http.ResponseWriter, r *http.Request) {
	rulesPath = "./rules/"
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

	rules := r.FormValue("rules")
	if err != nil {
		http.Error(w, "missing rules field", http.StatusBadRequest)
		return
	}

	// создать temp файл
	tmp, err := os.Create(filename)
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

	rulesPath += rules

	fmt.Println(rulesPath)

	cmd := exec.CommandContext(ctx, pythonBin, scriptPath, tmpPath, rulesPath)
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

	fmt.Println(string(out))

	// Формируем ответ — возвращаем stdout (ожидаем JSON от скрипта)
	resp := map[string]any{
		"exit_code": exitCode,
		"output":    string(out),
	}
	//fmt.Println(string(out))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
