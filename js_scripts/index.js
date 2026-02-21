const enterBtn = document.getElementById('enterBtn');
  const exitBtn = document.getElementById('exitBtn');
  const replaceTxt = document.getElementById('replacementText');
  const modalBackdrop = document.getElementById('modalBackdrop');
  const modalClose = document.getElementById('modalClose');

  const modalBackdrop1 = document.getElementById('modalBackdrop1');
  const modalClose1 = document.getElementById('modalClose1');

  const tabs = document.querySelectorAll('.tab');
  const loginFields = document.getElementById('loginFields');

  const registerFields = document.getElementById('registerFields');
  const regBtn = document.getElementById('regBtn');

  const authForm = document.getElementById('authForm');
  const signBtn = document.getElementById('signBtn');

  const fileInput = document.getElementById('fileInput');
  const fileLabelBtn = document.querySelector('.file-label');
  const scanBtn = document.getElementById('scanBtn');
  const resetBtn = document.getElementById('resetBtn');
  const statusText = document.getElementById('statusText');
  const progressBar = document.getElementById('progressBar');
  const resultText = document.getElementById('resultText');

  // Проверка авторизации при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Создаем запрос на проверку авторизации
    fetch('/api/check-auth')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.authenticated) {
                // Пользователь авторизован
                enterBtn.style.display = 'none';
                replaceTxt.style.display = 'inline';
                replaceTxt.textContent = data.email;
            } else {
                // Пользователь не авторизован
                enterBtn.style.display = '';
                replaceTxt.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error checking auth status:', error);
            // В случае ошибки показываем кнопку входа
            enterBtn.style.display = '';
            replaceTxt.style.display = 'none';
        });
});

// Функция для обновления интерфейса в зависимости от авторизации
function updateAuthUI(isAuthenticated, email = '') {
    if (isAuthenticated) {
        enterBtn.style.display = 'none';
        replaceTxt.style.display = 'inline';
        replaceTxt.textContent = email;
        exitBtn.style.display = 'inline'; // Показываем кнопку Exit
    } else {
        enterBtn.style.display = '';
        replaceTxt.style.display = 'none';
        exitBtn.style.display = 'none'; // Скрываем кнопку Exit
    }
}

exitBtn.addEventListener('click', () => {
    if (confirm('Вы уверены, что хотите выйти?')) {
        logoutUser();
    }
});

function logoutUser() {
    // Отправляем запрос на сервер для выхода
    fetch('/logout', {
        method: 'POST',
        credentials: 'same-origin' // Чтобы отправлялись куки
    })
    .then(response => {
        if (response.ok) {
            // Успешный выход - обновляем UI
            updateAuthUI(false);
            // Очищаем поля формы входа
            document.getElementById('loginEmail').value = '';
            document.getElementById('loginPassword').value = '';
            // Можно показать сообщение
            alert('Вы успешно вышли из системы');
        } else {
            throw new Error('Logout failed');
        }
    })
    .catch(error => {
        console.error('Logout error:', error);
        alert('Ошибка при выходе из системы');
    });
}

// Используйте ее при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    fetch('/api/check-auth')
        .then(response => response.json())
        .then(data => {
            updateAuthUI(data.authenticated, data.email);
            document.getElementById('regName').value = '';
            document.getElementById('regEmail').value = '';
        })
        .catch(error => {
            console.error('Auth check failed:', error);
            updateAuthUI(false);
        });
});

  // Modal open/close
  function openModal(){
    modalBackdrop.style.display = 'flex';
    modalBackdrop.setAttribute('aria-hidden','false');
    // focus on first input
    setTimeout(()=>document.getElementById('loginEmail').focus(), 100);
  }
  function closeModal(){
    modalBackdrop.style.display = 'none';
    modalBackdrop.setAttribute('aria-hidden','true');
  }

  enterBtn.addEventListener('click', openModal);
  modalClose.addEventListener('click', closeModal);
  modalBackdrop.addEventListener('click', (e)=>{
    if(e.target === modalBackdrop) closeModal();
  });

  // Tabs logic
  tabs.forEach(t=>{
    t.addEventListener('click', ()=>{
      tabs.forEach(x=>{
        x.classList.toggle('active', x===t);
        x.setAttribute('aria-selected', x===t ? 'true' : 'false');
      });
      const tab = t.dataset.tab;
      if(tab === 'login'){
        loginFields.style.display = '';
        registerFields.style.display = 'none';
      } else {
        loginFields.style.display = 'none';
        registerFields.style.display = '';
      }
    });
  });

  // Auth form submit (demo)
  authForm.addEventListener('submit', (e)=>{
    e.preventDefault();
    const activeTab = document.querySelector('.tab.active').dataset.tab;
    if(activeTab === 'login'){
      // simple demo validation
      const email = document.getElementById('loginEmail').value.trim();
      const pass = document.getElementById('loginPassword').value;
      if(!email || !pass){ alert('Заполните поля'); return; }
      // demo success
      alert('Успешный вход (демо).');
      closeModal();
    } else {
      const name = document.getElementById('regName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const p1 = document.getElementById('regPassword').value;
      const p2 = document.getElementById('regPassword2').value;
      if(!name || !email || !p1 || !p2){ alert('Заполните поля'); return; }
      if(p1.length < 8){ alert('Пароль должен быть минимум 8 символов'); return; }
      if(p1 !== p2){ alert('Пароли не совпадают'); return; }
      closeModal();
    }
  });

  regBtn.addEventListener('click', () => {
    const name = document.getElementById('regName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const p1 = document.getElementById('regPassword').value;
    const p2 = document.getElementById('regPassword2').value;
    if(!name || !email || !p1 || !p2){ alert('Заполните поля'); return; }
    if(p1.length < 8){ alert('Пароль должен быть минимум 8 символов'); return; }
    if(p1 !== p2){ alert('Пароли не совпадают'); return; }
    
    const form = new FormData();
    form.append('name', name);
    form.append('email', email);
    form.append('p1', p1);
        
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/reg', true);
        
    xhr.onreadystatechange = () => {
      if (xhr.readyState === 4) {
        if (xhr.status >= 200 && xhr.status < 300) {
          const res = JSON.parse(xhr.responseText);
          // Print output from /reg in main.go
          alert(res.output);
          document.getElementById('regName').value = '';
          document.getElementById('regEmail').value = '';
          document.getElementById('regPassword').value = '';
          document.getElementById('regPassword2').value = '';

          
        }
      }
    };
    xhr.send(form);
    closeModal();
  });

  signBtn.addEventListener('click', ()=> {
    const loginEmail = document.getElementById('loginEmail').value.trim();
    const loginPassword = document.getElementById('loginPassword').value.trim();
    
    const form = new FormData();
    form.append('email', loginEmail);
    form.append('p1', loginPassword);
    
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/sign', true);
    
    xhr.onreadystatechange = () => {
        if (xhr.readyState === 4) {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const res = JSON.parse(xhr.responseText);
                    if (res.output == 1) {
                        // Успешный вход
                        updateAuthUI(true, loginEmail);
                        closeModal();
                    } else {
                        alert('Ошибка входа: неверные данные');
                    }
                } catch (e) {
                    console.error('Error parsing response:', e);
                    alert('Ошибка при обработке ответа сервера');
                }
            }
        }
    };
    
    xhr.send(form);
});

  // File selection UI
  fileLabelBtn.addEventListener('click', ()=> fileInput.click());
  fileInput.addEventListener('change', ()=>{
    if(fileInput.files && fileInput.files.length){
      const f = fileInput.files[0];
      fileLabelBtn.textContent = `${f.name} (${Math.round(f.size/1024)} KB)`;
      scanBtn.disabled = false;
      statusText.textContent = 'Файл готов. Нажмите Scan для запуска анализа.';
      resultText.style.display = 'none';
      progressBar.style.width = '0%';
    } else {
      fileLabelBtn.textContent = 'Choose file';
      scanBtn.disabled = true;
      statusText.textContent = 'Your files are waiting to be scanned...';
    }
  });

  // Simulated scanning
  let scanning = false;
  scanBtn.addEventListener('click', () => {
  if (scanning) return;
  if (!fileInput.files.length) { alert('Выберите файл'); return; }

  const file = fileInput.files[0];
  const form = new FormData();
  form.append('file', file);

  scanning = true;
  scanBtn.disabled = true;
  resetBtn.disabled = true;
  resultText.style.display = 'none';
  statusText.textContent = 'Uploading...';
  progressBar.style.width = '0%';

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/scan', true);

  // отслеживаем прогресс загрузки
  xhr.upload.addEventListener('progress', (e) => {
    if (e.lengthComputable) {
      const percent = Math.round((e.loaded / e.total)); // резервируем 50% для загрузки
      progressBar.style.width = percent + '%';
    }
  });

  xhr.onreadystatechange = () => {
    if (xhr.readyState === 4) {
      // загрузка + сервер ответили
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const res = JSON.parse(xhr.responseText);
          // если Python вернул JSON в stdout, он будет в res.output
          let parsed = null;
          try { parsed = JSON.parse(res.output); } catch(e) { parsed = null; }

          if (parsed) {
            // показываем результат сканера
            if (parsed.infected) {
              resultText.style.color = 'var(--danger)';
              resultText.textContent = 'Внимание: файл содержит подозрительные сигнатуры — возможное вредоносное ПО.';
            } else {
              resultText.style.color = 'var(--success)';
              resultText.textContent = res.output;
            }
            // покажем дополнительные данные
            resultText.style.display = '';
            // опционально: показать детальный JSON в консоли или как текст
            console.log('scanner result:', parsed);
          } else {
            // если не удалось распарсить, покажем сырой output
            resultText.style.color = 'var(--muted)';
            resultText.textContent = res.output || '(no output)';
            resultText.style.display = '';
          }

          statusText.textContent = 'Scan complete.';
          progressBar.style.width = '100%';
        } catch (err) {
          statusText.textContent = 'Ошибка парсинга ответа от сервера';
          resultText.style.display = '';
          resultText.style.color = 'var(--danger)';
          resultText.textContent = 'Server error: ' + err.message;
        }
      } else {
        // ошибка сервера
        statusText.textContent = 'Server error: ' + xhr.status;
        resultText.style.display = '';
        resultText.style.color = 'var(--danger)';
        resultText.textContent = xhr.responseText || ('HTTP ' + xhr.status);
      }

      scanning = false;
      resetBtn.disabled = false;
      scanBtn.disabled = false;
    } else {
      // между загрузкой и готовностью можно показать "scanning..."
      if (xhr.readyState === 2 || xhr.readyState === 3) {
        // уменьшенно анимируем от 50% до 90% пока сервер думает
        const cur = parseFloat(progressBar.style.width) || 0;
        if (cur < 50) progressBar.style.width = '50%';
        statusText.textContent = 'Scanning on server...';
        // мелкая анимация к 90%
        let p = Math.max(50, cur);
        const tick = setInterval(() => {
          if (p < 90) {
            p += 1 + Math.random() * 2;
            progressBar.style.width = Math.min(p, 90) + '%';
          } else {
            clearInterval(tick);
          }
        }, 200);
      }
    }
  };

  // посылаем
  xhr.send(form);
});

  resetBtn.addEventListener('click', ()=>{
    fileInput.value = '';
    fileLabelBtn.textContent = 'Choose file';
    scanBtn.disabled = true;
    progressBar.style.width = '0%';
    statusText.textContent = 'Your files are waiting to be scanned...';
    resultText.style.display = 'none';
  });

  // Provide keyboard accessibility: Enter opens modal
  document.addEventListener('keydown', (e)=>{
    if(e.key === 'Enter' && document.activeElement === enterBtn){
      openModal();
    }
    if(e.key === 'Escape'){
      closeModal();
    }
  });

  // Small polish: simulate initial gentle progress to show liveliness
  (function gentlePulse(){
    let p=0,dir=1;
    setInterval(()=>{
      p += dir*0.6;
      if(p>8 || p<0) dir *= -1;
      document.querySelector('.logo').style.transform = `translateY(${p}px)`;
    }, 1200);
  })();