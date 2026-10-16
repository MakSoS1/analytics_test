@echo off
setlocal
cd /d "%~dp0"
echo Installing OPTIONAL RapidOCR with a separate Python virtual environment.
echo No existing Whisper, Ollama, CUDA packages or models will be altered.
where py >nul 2>&1
if errorlevel 1 (
 echo Python launcher not found. Install Python 3.11 or use browser Tesseract.js.
 pause
 exit /b 1
)
py -3.11 -m venv .ocr-venv
if errorlevel 1 (
 echo Cannot create isolated Python 3.11 environment.
 pause
 exit /b 1
)
".ocr-venv\Scripts\python.exe" -m pip install --disable-pip-version-check "rapidocr>=3.9.2,<4" "onnxruntime>=1.20,<2" pillow numpy
if errorlevel 1 (
 echo OCR dependencies installation failed; browser Tesseract.js still works.
 pause
 exit /b 1
)
".ocr-venv\Scripts\python.exe" scripts\rapidocr_local.py --probe
if errorlevel 1 (
 echo OCR probe failed; browser Tesseract.js still works.
 pause
 exit /b 1
)
echo Optional OCR installed. Start or restart START_WINDOWS.cmd and choose Auto / RapidOCR.
pause
