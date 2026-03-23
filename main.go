package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
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
	"strconv"
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

// archiveSem ограничивает число одновременно запущенных процессов yr при
// сканировании архива. Инициализируется в main() на основе числа CPU.
var archiveSem chan struct{}

// fileStore хранит сведения о загруженных файлах, чтобы их можно было
// вернуть пользователю или переместить в карантин после сканирования.
type storedFileMeta struct {
	ID             string
	Email          string
	OriginalName   string
	OriginalPath   string    // путь к файлу на клиентском ПК (из FormData)
	UploadPath     string
	QuarantinePath string
	ThreatsList    string    // угрозы через "|", заполняется после сканирования
	Quarantined    bool
	CreatedAt      time.Time
}

var fileStore = struct {
	sync.RWMutex
	m map[string]*storedFileMeta
}{
	m: make(map[string]*storedFileMeta),
}

func main() {
	// Разрешаем не более max(1, GOMAXPROCS-1) одновременных процессов yr,
	// оставляя хотя бы одно ядро свободным для самого сервера.
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
	http.HandleFunc("/api/rule-content", ruleContentHandler)
	http.HandleFunc("/api/save-rule", saveRuleHandler)
	http.HandleFunc("/api/download-rules", downloadRulesHandler)
	http.HandleFunc("/road", roadHandler)
	http.HandleFunc("/history", histHandler)
	http.HandleFunc("/api/scanfiles", scanfilesHandler)
	http.HandleFunc("/api/restore-file", restoreFileHandler)
	http.HandleFunc("/api/quarantine-file", quarantineFileHandler)

	fmt.Println("Starting server at :8025")
	if err := http.ListenAndServe(":8025", nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Println("server error:", err)
	}
}

// scanPeriodStatus — результат серверного анализа периода, возвращается фронтенду.
// status:
//
//	"ok"            — есть записи, files заполнен
//	"empty"         — период корректный, но записей нет
//	"future"        — весь выбранный период ещё не наступил
//	"no_data_yet"   — период в далёком прошлом, до начала работы сервиса
type scanPeriodStatus struct {
	Status       string           `json:"status"`        // итоговый код
	Message      string           `json:"message"`       // человекочитаемый текст
	Hint         string           `json:"hint"`          // подсказка для пользователя
	TotalScans   int              `json:"total_scans"`   // всего записей за период
	TotalThreats int              `json:"total_threats"` // сумма угроз за период
	Files        []map[string]any `json:"files"`         // строки таблицы (может быть nil)
}

func scanfilesHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("email")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	const dateFmt = "2006-01-02"
	now := time.Now().UTC().Truncate(24 * time.Hour) // начало сегодняшнего дня (UTC)

	var fromTime, toTime time.Time
	hasFrom, hasTo := false, false

	if fs := r.URL.Query().Get("from"); fs != "" {
		if t, err := time.Parse(dateFmt, fs); err == nil {
			fromTime = t.UTC()
			hasFrom = true
		}
	}
	if ts := r.URL.Query().Get("to"); ts != "" {
		if t, err := time.Parse(dateFmt, ts); err == nil {
			toTime = t.UTC().Add(24*time.Hour - time.Second) // конец дня включительно
			hasTo = true
		}
	}

	// ── Серверный анализ периода ─────────────────────────────────────────────
	// 1. Весь диапазон лежит в будущем
	if hasFrom && fromTime.After(now) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanPeriodStatus{
			Status:  "future",
			Message: "Этот период ещё не наступил",
			Hint:    "Выберите даты не позднее сегодняшнего дня",
		})
		return
	}

	// 2. Верхняя граница до запуска сервиса (условно — до 2000-01-01)
	serviceEpoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if hasTo && toTime.Before(serviceEpoch) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanPeriodStatus{
			Status:  "no_data_yet",
			Message: "За данный период записей нет",
			Hint:    "Сканирование ещё не проводилось в этот период",
		})
		return
	}

	// ── Запрос к БД ──────────────────────────────────────────────────────────
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

	var files []map[string]any
	totalThreats := 0

	for rows.Next() {
		var id, filename, size, threatsCount, threatsList string
		var date time.Time

		if err := rows.Scan(&id, &c.Value, &filename, &size, &date, &threatsCount, &threatsList); err != nil {
			http.Error(w, "scan error", http.StatusInternalServerError)
			return
		}

		var threatNames []string
		if threatsList != "" {
			for _, t := range strings.Split(threatsList, "|") {
				if t != "" {
					threatNames = append(threatNames, t)
				}
			}
		}

		if n, _ := strconv.Atoi(threatsCount); n > 0 {
			totalThreats += n
		}

		files = append(files, map[string]any{
			"filename":      filename,
			"size":          size,
			"date":          date.Format("02-01-2006"),
			"threats_count": threatsCount,
			"threats_list":  threatNames,
		})
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "rows error", http.StatusInternalServerError)
		return
	}

	// ── Формируем итоговый ответ с серверным анализом ────────────────────────
	w.Header().Set("Content-Type", "application/json")

	if len(files) == 0 {
		json.NewEncoder(w).Encode(scanPeriodStatus{
			Status:  "empty",
			Message: "За данный период ничего не было просканировано",
			Hint:    "Попробуйте выбрать другой диапазон дат",
		})
		return
	}

	json.NewEncoder(w).Encode(scanPeriodStatus{
		Status:       "ok",
		Message:      "",
		TotalScans:   len(files),
		TotalThreats: totalThreats,
		Files:        files,
	})
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

	absPath, _ := filepath.Abs("./rules/" + filename)
	resp := map[string]any{
		"message": "file uploaded successfully",
		"path":    absPath,
		"name":    filename,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ruleContentHandler — GET /api/rule-content?name=<filename>
// Returns the text content of a YARA rule file from ./rules/
func ruleContentHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("email"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := filepath.Base(r.URL.Query().Get("name"))
	if name == "" || name == "." {
		http.Error(w, "missing name parameter", http.StatusBadRequest)
		return
	}
	rulePath := filepath.Join(rulesDir, name)
	data, err := os.ReadFile(rulePath)
	if err != nil {
		http.Error(w, "cannot read file: "+err.Error(), http.StatusNotFound)
		return
	}
	resp := map[string]any{
		"name":    name,
		"content": string(data),
		"path":    rulePath,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// saveRuleHandler — POST /api/save-rule
// Saves edited YARA rule content back to ./rules/<name>
func saveRuleHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("email"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	name := filepath.Base(body.Name)
	if name == "" || name == "." {
		http.Error(w, "invalid file name", http.StatusBadRequest)
		return
	}
	rulePath := filepath.Join(rulesDir, name)
	if err := os.WriteFile(rulePath, []byte(body.Content), 0644); err != nil {
		http.Error(w, "cannot write file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	absPath, _ := filepath.Abs(rulePath)
	resp := map[string]any{
		"message": "rule saved successfully",
		"path":    absPath,
		"name":    name,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// downloadRulesHandler — POST /api/download-rules
// Запускает ./scripts/rules/download.py и возвращает результат выполнения.
func downloadRulesHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("email"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Определяем абсолютный путь к директории скрипта, чтобы файлы сохранялись
	// именно туда, а не в рабочую директорию сервера.
	scriptDir, err := filepath.Abs("./scripts/rules")
	if err != nil {
		http.Error(w, "cannot resolve script path: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cmd := exec.CommandContext(ctx, "python3", filepath.Join(scriptDir, "download.py"))
	// Dir задаёт рабочую директорию процесса — скрипт будет видеть её как текущую,
	// поэтому open("file.yar", "w") и os.getcwd() будут указывать на ./scripts/rules/
	cmd.Dir = scriptDir
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":     false,
			"error":  "script timeout",
			"output": string(out),
		})
		return
	}

	ok := err == nil
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	// После успешного выполнения скрипта перемещаем downloaded_rules.yar
	// из ./scripts/rules/ в ./rules/ (рядом с main.go).
	if ok {
		src := filepath.Join(scriptDir, "downloaded_rules.yar")
		dst := filepath.Join("./rules", "downloaded_rules.yar")

		dstAbs, _ := filepath.Abs(dst)

		if moveErr := os.Rename(src, dst); moveErr != nil {
			// os.Rename может не сработать при перемещении между разными
			// файловыми системами — fallback: копировать + удалить источник.
			if copyErr := copyFile(src, dst); copyErr != nil {
				ok = false
				errMsg = "script ok, but failed to move file: " + copyErr.Error()
			} else {
				os.Remove(src)
			}
		}

		if ok {
			log.Printf("downloaded_rules.yar moved to %s", dstAbs)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":     ok,
		"output": string(out),
		"error":  errMsg,
	})
}

// copyFile копирует файл src в dst — используется как fallback для os.Rename
// при перемещении между разными точками монтирования.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func ensureQuarantineKey() ([]byte, error) {
	keyPath := "./.quarantine.key"
	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) == 32 {
			return data, nil
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptBytes(plaintext []byte) ([]byte, error) {
	key, err := ensureQuarantineKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptBytes(ciphertext []byte) ([]byte, error) {
	key, err := ensureQuarantineKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, enc := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, enc, nil)
}

func newScanID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func registerUploadedFile(email, originalName, originalPath string, data []byte) (string, string, error) {
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", "", err
	}
	id := newScanID()
	safeName := filepath.Base(originalName)
	uploadPath := filepath.Join(uploadDir, id+"_"+safeName)
	if err := os.WriteFile(uploadPath, data, 0644); err != nil {
		return "", "", err
	}
	fileStore.Lock()
	fileStore.m[id] = &storedFileMeta{
		ID:             id,
		Email:          email,
		OriginalName:   safeName,
		OriginalPath:   originalPath,
		UploadPath:     uploadPath,
		QuarantinePath: filepath.Join("./quarantine", id+"_"+safeName+".enc"),
		CreatedAt:      time.Now(),
	}
	fileStore.Unlock()
	return id, uploadPath, nil
}

func getStoredFile(id string) (*storedFileMeta, bool) {
	fileStore.RLock()
	defer fileStore.RUnlock()
	m, ok := fileStore.m[id]
	return m, ok
}

func quarantineStoredFile(meta *storedFileMeta) error {
	if meta == nil {
		return errors.New("missing file metadata")
	}
	if meta.Quarantined {
		return nil
	}

	plain, err := os.ReadFile(meta.UploadPath)
	if err != nil {
		return err
	}
	encrypted, err := encryptBytes(plain)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(meta.QuarantinePath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(meta.QuarantinePath, encrypted, 0600); err != nil {
		return err
	}

	if err := os.Remove(meta.UploadPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	meta.Quarantined = true
	return nil
}

func restoreFileHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("email"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		http.Error(w, "missing scan_id", http.StatusBadRequest)
		return
	}

	meta, ok := getStoredFile(scanID)
	if !ok {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	cookie, err := r.Cookie("email")
	if err != nil || cookie.Value != meta.Email {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var data []byte
	if meta.Quarantined {
		if meta.QuarantinePath == "" {
			http.Error(w, "quarantine path is missing", http.StatusInternalServerError)
			return
		}
		encData, err := os.ReadFile(meta.QuarantinePath)
		if err != nil {
			http.Error(w, "cannot read quarantined file: "+err.Error(), http.StatusNotFound)
			return
		}
		data, err = decryptBytes(encData)
		if err != nil {
			http.Error(w, "cannot decrypt quarantined file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		data, err = os.ReadFile(meta.UploadPath)
		if err != nil {
			http.Error(w, "cannot read file: "+err.Error(), http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", meta.OriginalName))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func quarantineFileHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("email"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		ScanID string `json:"scan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.ScanID == "" {
		http.Error(w, "missing scan_id", http.StatusBadRequest)
		return
	}

	meta, ok := getStoredFile(body.ScanID)
	if !ok {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	cookie, err := r.Cookie("email")
	if err != nil || cookie.Value != meta.Email {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := quarantineStoredFile(meta); err != nil {
		http.Error(w, "cannot quarantine file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Пишем запись в таблицу scanVPO
	quarantinedAt := time.Now()
	if err := addScanVPO(
		meta.OriginalName,
		meta.OriginalPath,
		meta.QuarantinePath,
		meta.ThreatsList,
		quarantinedAt,
		cookie.Value,
	); err != nil {
		log.Printf("addScanVPO error: %v", err)
		// Не прерываем ответ — запись в лог, карантин уже выполнен
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"scan_id":     body.ScanID,
		"quarantined": true,
	})
}

// addScanVPO записывает информацию о помещённом в карантин файле в таблицу scanVPO.
// DDL для таблицы:
//
//	CREATE TABLE scanVPO (
//	    id               SERIAL PRIMARY KEY,
//	    filename         TEXT        NOT NULL,
//	    original_path    TEXT        NOT NULL DEFAULT '',
//	    quarantine_path  TEXT        NOT NULL,
//	    threats          TEXT        NOT NULL DEFAULT '',
//	    quarantined_at   TIMESTAMPTZ NOT NULL,
//	    quarantined_by   TEXT        NOT NULL
//	);
func addScanVPO(filename, originalPath, quarantinePath, threats string, quarantinedAt time.Time, quarantinedBy string) error {
	conn, err := pgx.Connect(context.Background(), "postgres://ilya:4suh12iiyu@localhost:5432/web_scanner")
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(context.Background(),
		`INSERT INTO scanVPO (filename, original_path, quarantine_path, threats, quarantined_at, quarantined_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		filename, originalPath, quarantinePath, threats, quarantinedAt, quarantinedBy,
	)
	return err
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

	// threats_list — список найденных угроз через «|», добавляется в БД миграцией:
	// ALTER TABLE scanfiles ADD COLUMN IF NOT EXISTS threats_list TEXT DEFAULT '';
	_, err = conn.Exec(context.Background(),
		"insert into scanfiles (email, filename, size, date, threats_count, threats_list) values ($1, $2, $3, $4, $5, $6)",
		email, filename, size, date, threats, threatsList)
	if err != nil {
		log.Fatal(err)
	}
}

// ScanResult содержит результат проверки одного файла правилами YARA.
type ScanResult struct {
	File    string   // имя проверяемого файла
	Threats []string // список сработавших правил
}

// yaraScanOutput — структура JSON, которую выводит `yr scan --output-format json`.
type yaraScanOutput struct {
	Matches []struct {
		Rule string `json:"rule"`
	} `json:"matches"`
}

// runYaraScan запускает бинарник yr для одного файла на диске и возвращает
// список сработавших правил. Это Go-замена logic из analyze.py.
func runYaraScan(ctx context.Context, rulesFile, targetPath string) ([]string, error) {
	outFile := targetPath + ".yara_out.json"
	defer os.Remove(outFile)

	// yr scan --disable-warnings --output-format json <rules> <target> > <out>
	cmd := exec.CommandContext(ctx,
		"./scripts/yr", "scan",
		"--disable-warnings",
		"--output-format", "json",
		rulesFile, targetPath,
	)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard

	// yr возвращает exit code 1 при обнаружении совпадений — это нормально
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

// scanFileBytes сохраняет байты во временный файл, прогоняет YARA и удаляет
// временный файл. Используется и для обычных файлов, и для файлов из архива.
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

// archiveEntry — задание для worker-а: имя файла + его байты.
type archiveEntry struct {
	name string
	data []byte
}

// scanArchive распаковывает ZIP-архив в памяти и сканирует каждый вложенный
// файл параллельно — число воркеров ограничено семафором archiveSem (= GOMAXPROCS-1).
// Порядок результатов соответствует порядку файлов в архиве.
func scanArchive(ctx context.Context, rulesFile string, archiveData []byte) ([]ScanResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if err != nil {
		return nil, fmt.Errorf("cannot open zip: %w", err)
	}

	// Собираем только файлы (не директории) и читаем их содержимое заранее,
	// чтобы не держать zip.ReadCloser открытым внутри goroutine.
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

	// Результаты аллоцируем заранее — каждая goroutine пишет в свой индекс,
	// поэтому никакой синхронизации на запись не нужно.
	results := make([]ScanResult, len(entries))

	// Канал задач: индекс в слайсе entries.
	type job struct{ idx int }
	jobs := make(chan job, len(entries))
	for i := range entries {
		jobs <- job{i}
	}
	close(jobs)

	// Каждый файл получает отдельную goroutine, но перед запуском процесса yr
	// захватывает слот в archiveSem — это гарантирует, что одновременно работает
	// не более (GOMAXPROCS-1) тяжёлых процессов независимо от размера архива.
	var wg sync.WaitGroup
	for j := range jobs {
		j := j // захватываем для goroutine
		e := entries[j.idx]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.data == nil {
				results[j.idx] = ScanResult{File: e.name}
				return
			}
			// Ждём свободный слот или отмену контекста
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

	// Читаем файл целиком — нужен для MD5, сохранения на сервере и анализа
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "failed to read uploaded file", http.StatusInternalServerError)
		return
	}

	// MD5 считается на стороне сервера
	rawHash := md5.Sum(fileBytes)
	fileHash := hex.EncodeToString(rawHash[:])

	c, err := r.Cookie("email")
	if err != nil || c.Value == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Семафор параллелизма
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		http.Error(w, "server busy, try later", http.StatusTooManyRequests)
		return
	}

	// Для архивов используем увеличенный таймаут, т.к. файлов может быть много
	isZip := strings.HasSuffix(strings.ToLower(filename), ".zip")
	timeout := scanTimeout
	if isZip {
		timeout = archiveScanTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fullRulesPath := rulesPath + rules

	// Читаем путь к файлу на клиентском ПК (браузер передаёт через FormData)
	originalPath := r.FormValue("original_path")

	// Сохраняем загруженный файл на сервере для последующего возврата/карантина.
	scanID, uploadPath, err := registerUploadedFile(c.Value, filename, originalPath, fileBytes)
	if err != nil {
		http.Error(w, "internal error creating upload record", http.StatusInternalServerError)
		return
	}
	// --- Сканирование: ZIP-архив или обычный файл ---
	var scanResults []ScanResult

	if isZip {
		// Распаковываем архив в памяти и сканируем файлы параллельно
		archiveResults, err := scanArchive(ctx, fullRulesPath, fileBytes)
		if err != nil {
			http.Error(w, "archive scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		scanResults = archiveResults
	} else {
		res, err := runYaraScan(ctx, fullRulesPath, uploadPath)
		if err != nil {
			log.Printf("yara scan error: %v", err)
		}
		scanResults = []ScanResult{{File: filename, Threats: res}}
	}

	if ctx.Err() == context.DeadlineExceeded {
		http.Error(w, "scan timeout", http.StatusGatewayTimeout)
		return
	}

	// Подсчитываем суммарное количество угроз по всем файлам
	threatsCount := 0
	for _, r := range scanResults {
		threatsCount += len(r.Threats)
	}
	fmt.Printf("Threats found: %d across %d file(s)\n", threatsCount, len(scanResults))

	// Формируем текстовый вывод в формате совместимом с фронтендом:
	// Check:
	// RuleName1
	// RuleName2 (из файла archive/foo.exe)
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

	// Собираем список угроз в строку через "|" для хранения в БД
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

	// Сохраняем список угроз в meta, чтобы quarantineFileHandler мог записать его в БД
	if meta, ok := getStoredFile(scanID); ok {
		fileStore.Lock()
		meta.ThreatsList = threatsList
		fileStore.Unlock()
	}

	currentTime := time.Now()
	c, err = r.Cookie("email")
	if err == nil {
		addScanFiles(c.Value, filename, size, currentTime.Format("01-02-2006"), threatsCount, threatsList)
	}

	resp := map[string]any{
		"exit_code":     0,
		"output":        outputStr,
		"hash":          fileHash,
		"threats_count": threatsCount,
		"scan_id":       scanID,
		"file_name":     filename,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
