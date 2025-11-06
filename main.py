import os
import io
import fitz  # PyMuPDF
import sqlite3
import json
import httpx  # Librăria nouă pentru apeluri API
from docx import Document
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Security
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
from typing import Optional

# --- Importuri pentru JWT (Autentificare) ---
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# ! Asigură-te că ai instalat:
# pip install fastapi uvicorn python-docx pymupdf "passlib[bcrypt]" "python-jose[cryptography]" httpx

# ----------------------------------------------------------------------
# 1. CONFIGURARE BAZĂ DE DATE ȘI AUTENTIFICARE
# ----------------------------------------------------------------------

DATABASE_URL = "user_accounts.db"

# --- Configurare JWT (Token-uri) ---
SECRET_KEY = "CHEIE_SECRETA_SUPER_COMPLICATA_DE_SCHIMBAT"  # Schimbă asta!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login_for_token") # Folosit pentru Depends

# --- Modele Pydantic ---
class UserIn(BaseModel):
    email: str
    password: str

class ResetPasswordIn(BaseModel):
    email: str
    secretKey: str
    newPassword: str

class TokenData(BaseModel):
    email: Optional[str] = None

# --- Funcții Bază de Date ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Creează ambele tabele: users și analyses."""
    conn = get_db_connection()
    try:
        # Tabela de utilizatori
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        """)
        # Tabela de analize (actualizată)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_content BLOB NOT NULL,
                analysis_json TEXT, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        """)
        conn.commit()
        print("Tabelele 'users' și 'analyses' sunt gata.")
    except Exception as e:
        print(f"Eroare la crearea tabelelor: {e}")
    finally:
        conn.close()

create_tables()

# --- Funcții Utilitare (Hashing și JWT) ---
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user_email(token: str = Security(oauth2_scheme)) -> str:
    """Funcție helper pentru a valida token-ul și a returna email-ul."""
    credentials_exception = HTTPException(
        status_code=401,
        detail="Token invalid sau expirat",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        return email
    except JWTError:
        raise credentials_exception

async def get_user_id_from_email(email: str) -> int:
    """Obține ID-ul utilizatorului din email (pentru a-l folosi în baza de date)."""
    conn = get_db_connection()
    user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if user:
        return user['id']
    raise HTTPException(status_code=404, detail="Utilizatorul nu a fost găsit.")

# ----------------------------------------------------------------------
# 2. INIȚIALIZARE FASTAPI
# ----------------------------------------------------------------------

app = FastAPI(title="Resume Analyzer (Middleware)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")

# ----------------------------------------------------------------------
# 3. FUNCȚII DE PARSARE (Membru 1)
# ----------------------------------------------------------------------
# (Funcțiile extract_text_from_pdf și extract_text_from_docx rămân neschimbate)
def extract_text_from_pdf(file_stream: io.BytesIO) -> str:
    text = ""
    try:
        doc = fitz.open(stream=file_stream.read(), filetype="pdf")
        for page in doc:
            text += page.get_text("text") + "\n"
        doc.close()
    except Exception as e:
        print(f"Eroare la parsarea PDF: {e}")
        raise HTTPException(status_code=500, detail="Eroare la parsarea PDF.")
    return text.strip()

def extract_text_from_docx(file_stream: io.BytesIO) -> str:
    try:
        document = Document(file_stream)
        text = "\n".join([paragraph.text for paragraph in document.paragraphs])
    except Exception as e:
        print(f"Eroare la parsarea DOCX: {e}")
        raise HTTPException(status_code=500, detail="Eroare la parsarea DOCX.")
    return text.strip()

# ----------------------------------------------------------------------
# 4. ENDPOINTS PUBLICE (LOGIN/REGISTER/RESET)
# ----------------------------------------------------------------------

@app.get("/", response_class=RedirectResponse)
async def serve_login_page():
    return RedirectResponse(url="/static/login.html")

@app.post("/api/register")
async def register_user(user: UserIn):
    # (Logica de înregistrare rămâne neschimbată)
    conn = get_db_connection()
    try:
        existing_user = conn.execute("SELECT id FROM users WHERE email = ?", (user.email,)).fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="Adresa de email este deja folosită.")
        hashed_password = hash_password(user.password)
        conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (user.email, hashed_password))
        conn.commit()
        return {"message": "Utilizator înregistrat cu succes!"}
    finally:
        conn.close()

@app.post("/api/login")
async def login_for_access_token(user: UserIn): # <-- MODIFICARE: Folosim UserIn în loc de OAuth2PasswordRequestForm
    """Endpoint-ul de login care returnează un token JWT."""
    conn = get_db_connection()
    # Folosim user.email și user.password
    db_user = conn.execute("SELECT password FROM users WHERE email = ?", (user.email,)).fetchone()
    conn.close()

    if not db_user or not verify_password(user.password, db_user['password']):
        raise HTTPException(
            status_code=401,
            detail="Email sau parolă incorectă.", # Acum va returna acest text
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires # Folosim user.email
    )
    return {"access_token": access_token, "token_type": "bearer", "redirect": "/static/dashboard.html"}


@app.post("/api/reset-password")
async def reset_password(data: ResetPasswordIn):
    # (Logica de resetare parolă rămâne neschimbată)
    SECRET_KEY_LOCAL = "123456" 
    if data.secretKey != SECRET_KEY_LOCAL:
        raise HTTPException(status_code=401, detail="Cheia secretă este incorectă.")
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id FROM users WHERE email = ?", (data.email,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Email-ul nu a fost găsit.")
        
        hashed_password = hash_password(data.newPassword)
        conn.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, data.email))
        conn.commit()
        return {"message": "Parola a fost resetată cu succes!"}
    finally:
        conn.close()

# ----------------------------------------------------------------------
# 5. ENDPOINT-URI PROTEJATE (ISTORIC, ANALIZĂ)
# ----------------------------------------------------------------------

# --- URL-UL CELUILALT API AL TĂU (CEL DE AI) ---
# --- SCHIMBĂ ACEST URL CU CEL CORECT PENTRU TINE ---
OTHER_AI_API_URL = "http://localhost:8001/analyze_cv" 
# -------------------------------------------------

@app.post("/api/analyze-resume/")
async def analyze_resume_and_call_ai(
    resume_file: UploadFile = File(...),
    job_description: str = "",
    current_user_email: str = Depends(get_current_user_email) # <-- Autentificare
):
    """
    1. Parsează fișierul.
    2. Apelează al doilea API (AI-ul tău local).
    3. Salvează rezultatul AI-ului.
    4. Returnează rezultatul AI-ului către frontend.
    """
    
    user_id = await get_user_id_from_email(current_user_email)
    
    # --- 1. Parsarea fișierului ---
    file_bytes = await resume_file.read()
    file_stream = io.BytesIO(file_bytes)
    file_extension = os.path.splitext(resume_file.filename)[1].lower()
    
    if file_extension == '.pdf':
        resume_text = extract_text_from_pdf(file_stream)
    elif file_extension == '.docx':
        resume_text = extract_text_from_docx(file_stream)
    else:
        raise HTTPException(status_code=400, detail="Extensie neacceptată.")
    
    if not resume_text:
        raise HTTPException(status_code=422, detail="Fișierul este gol.")

    # --- 2. Apelarea celui de-al doilea API (AI-ul tău local) ---
    ai_json_response = None
    try:
        async with httpx.AsyncClient() as client:
            print(f"Trimitere text către API-ul AI la {OTHER_AI_API_URL}...")
            response = await client.post(
                OTHER_AI_API_URL,
                json={"cv_text": resume_text, "job_description": job_description},
                timeout=90.0 # Timeout de 90 secunde
            )
            
            response.raise_for_status() # Ridică eroare dacă statusul e 4xx sau 5xx
            ai_json_response = response.json() # Răspunsul JSON de la AI
            print("Răspuns primit de la AI.")

    except httpx.ConnectError as e:
        print(f"Eroare de conexiune la AI API: {e}")
        raise HTTPException(status_code=503, detail=f"Nu s-a putut conecta la serviciul de AI. Rulează celălalt API? ({e})")
    except httpx.HTTPStatusError as e:
        print(f"Eroare HTTP de la AI API: {e}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Eroare de la serviciul de AI: {e.response.text}")
    except Exception as e:
        print(f"Eroare necunoscută la apelarea AI: {e}")
        raise HTTPException(status_code=500, detail=f"Eroare necunoscută la procesarea AI: {e}")

    if not ai_json_response:
         raise HTTPException(status_code=500, detail="Serviciul AI nu a returnat un răspuns.")

    # --- 3. Salvarea rezultatului AI-ului în Baza de Date ---
    try:
        conn = get_db_connection()
        # Salvăm fișierul original (file_bytes) și răspunsul AI (ai_json_response)
        conn.execute(
            "INSERT INTO analyses (user_id, filename, file_content, analysis_json, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, resume_file.filename, file_bytes, json.dumps(ai_json_response), datetime.utcnow())
        )
        conn.commit()
    except Exception as e:
        print(f"Eroare la salvarea în baza de date: {e}")
        # Nu oprim fluxul dacă salvarea eșuează, doar raportăm
    finally:
        conn.close()

    # --- 4. Returnarea rezultatului AI-ului către frontend ---
    return ai_json_response


@app.get("/api/history")
async def get_history(current_user_email: str = Depends(get_current_user_email)):
    """Returnează lista de analize (fără fișiere) pentru utilizatorul curent."""
    user_id = await get_user_id_from_email(current_user_email)
    conn = get_db_connection()
    history = conn.execute(
        "SELECT id, filename, timestamp FROM analyses WHERE user_id = ? ORDER BY timestamp DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in history]


@app.get("/api/analysis/{analysis_id}")
async def get_analysis_detail(analysis_id: int, current_user_email: str = Depends(get_current_user_email)):
    """Returnează JSON-ul analizei AI salvate."""
    user_id = await get_user_id_from_email(current_user_email)
    conn = get_db_connection()
    analysis = conn.execute(
        "SELECT analysis_json FROM analyses WHERE id = ? AND user_id = ?",
        (analysis_id, user_id)
    ).fetchone()
    conn.close()
    if not analysis or not analysis['analysis_json']:
        raise HTTPException(status_code=404, detail="Analiza nu a fost găsită.")
    return json.loads(analysis['analysis_json']) # Returnează JSON-ul parsat


@app.get("/api/download-file/{analysis_id}")
async def download_original_file(analysis_id: int, current_user_email: str = Depends(get_current_user_email)):
    """Descarcă fișierul original (PDF/DOCX) salvat."""
    user_id = await get_user_id_from_email(current_user_email)
    conn = get_db_connection()
    file_data = conn.execute(
        "SELECT file_content, filename FROM analyses WHERE id = ? AND user_id = ?",
        (analysis_id, user_id)
    ).fetchone()
    conn.close()
    if not file_data:
        raise HTTPException(status_code=404, detail="Fișierul nu a fost găsit.")
    
    # Detectează tipul de conținut
    media_type = "application/octet-stream"
    if file_data['filename'].lower().endswith('.pdf'):
        media_type = "application/pdf"
    elif file_data['filename'].lower().endswith('.docx'):
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    return Response(
        content=file_data['file_content'], 
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=\"{file_data['filename']}\""}
    )