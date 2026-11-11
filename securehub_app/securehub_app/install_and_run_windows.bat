@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher (py) tidak ditemukan. Install Python 3.10 atau lebih baru terlebih dahulu.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto error
)
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
if errorlevel 1 goto error
python -m pip install -r requirements.txt
if errorlevel 1 goto error
python -m streamlit run app.py
if errorlevel 1 goto error
goto end
:error
echo.
echo Terjadi kesalahan saat instalasi atau menjalankan SecureHub.
pause
:end
endlocal
