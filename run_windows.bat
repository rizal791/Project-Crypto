@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment belum tersedia. Jalankan install_and_run_windows.bat dahulu.
  pause
  exit /b 1
)
call ".venv\Scripts\activate.bat"
python -m streamlit run app.py
endlocal
