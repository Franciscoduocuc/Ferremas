from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from dotenv import load_dotenv
from pydantic import BaseModel
import httpx
import os
import json
from auth import create_access_token, verify_password
from users import fake_users_db

load_dotenv()

app = FastAPI()

FERREMAS_API_URL = os.getenv("FERREMAS_API_URL")
FERREMAS_TOKEN = os.getenv("FERREMAS_TOKEN")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

headers = {
    "x-authentication": FERREMAS_TOKEN
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class NovedadPayload(BaseModel):
    es_novedad: bool

novedades = {}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")
    if not verify_password(form_data.password, user_dict["hashed_password"]):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")

    token = create_access_token(data={"sub": user_dict["username"], "role": user_dict["role"]})
    return {"access_token": token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar el token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        return {"username": username, "role": role}
    except JWTError:
        raise credentials_exception

@app.get("/")
def read_root():
    return {"mensaje": "Hola FERREMAS"}

@app.get("/productos")
async def get_productos():
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{FERREMAS_API_URL}/data/articulos", headers=headers)
        return response.json()

@app.get("/productos/{producto_id}")
async def get_producto(producto_id: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{FERREMAS_API_URL}/data/articulos/{producto_id}", headers=headers)
        if response.status_code == 200:
            try:
                return response.json()
            except Exception as e:
                return JSONResponse(
                    content={"error": "Error al procesar JSON", "detalle": str(e)},
                    status_code=500
                )
        else:
            return JSONResponse(
                content={"error": "Producto no encontrado", "producto_id": producto_id},
                status_code=response.status_code
            )

@app.get("/sucursales")
async def get_sucursales():
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{FERREMAS_API_URL}/data/sucursales", headers=headers)
        return response.json()

@app.get("/sucursales/{sucursal_id}")
async def get_sucursal(sucursal_id: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{FERREMAS_API_URL}/data/sucursales/{sucursal_id}", headers=headers)
        return response.json()

@app.get("/vendedores")
async def get_vendedores(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="No tienes permiso para ver esta información")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{FERREMAS_API_URL}/data/vendedores", headers=headers)
        return response.json()

@app.get("/vendedores/{vendedor_id}")
async def get_vendedor(vendedor_id: str, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="No tienes permiso para ver esta información")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{FERREMAS_API_URL}/data/vendedores/{vendedor_id}", headers=headers)
        return response.json()

@app.get("/sucursales_con_vendedores")
async def get_sucursales_con_vendedores(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="No tienes permiso para ver esta información")
    async with httpx.AsyncClient() as client:
        sucursales_resp = await client.get(f"{FERREMAS_API_URL}/data/sucursales", headers=headers)
        vendedores_resp = await client.get(f"{FERREMAS_API_URL}/data/vendedores", headers=headers)
        sucursales = sucursales_resp.json()
        vendedores = vendedores_resp.json()
        return [
            {
                "id_sucursal": s["id"],
                "localidad": s["localidad"],
                "id_vendedor": v["id"],
                "nombre": v["nombre"],
                "email": v["email"]
            }
            for v in vendedores
            for s in sucursales
            if s["id"] == v["sucursal"]
        ]

@app.put("/productos/{producto_id}/marcar_novedad")
async def marcar_novedad(producto_id: str, payload: NovedadPayload, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="No tienes permiso para esta acción")
    if payload.es_novedad:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{FERREMAS_API_URL}/data/articulos/{producto_id}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                novedades[producto_id] = {
                    "id": data.get("id", producto_id),
                    "nombre": data.get("nombre", f"Producto {producto_id}")
                }
                return {"mensaje": f"Producto {producto_id} marcado como novedad"}
            else:
                return JSONResponse(content={"error": "Producto no encontrado en la API"}, status_code=404)
    else:
        if producto_id in novedades:
            del novedades[producto_id]
        return {"mensaje": f"Producto {producto_id} desmarcado como novedad"}

@app.get("/productos/novedades")
async def obtener_novedades(user: dict = Depends(get_current_user)):
    return list(novedades.values())

@app.get("/conversion_dinero")
async def cambio_clp_usd(
    origen: str = Query(..., description="Divisa de origen: CLP o USD"),
    cantidad: float = Query(..., description="Cantidad a convertir")
):
    origen = origen.upper()
    if origen not in ["CLP", "USD"]:
        return JSONResponse(status_code=400, content={"error": "Solo se permite CLP o USD como divisa de origen"})

    url = "https://api.exchangerate-api.com/v4/latest/USD"

    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        if response.status_code != 200:
            return JSONResponse(status_code=500, content={"error": "No se pudo obtener la tasa de cambio"})

        tasas = response.json().get("rates", {})
        tasa_clp = tasas.get("CLP")
        if not tasa_clp:
            return JSONResponse(status_code=500, content={"error": "No se encontró la tasa para CLP"})

    if origen == "USD":
        resultado = cantidad * tasa_clp
        destino = "CLP"
    else:
        resultado = cantidad / tasa_clp
        destino = "USD"

    return {
        "origen": origen,
        "destino": destino,
        "cantidad": cantidad,
        "resultado": round(resultado, 2),
        "tasa_CLP_USD": tasa_clp
    }

@app.get("/solo-admin")
def solo_admin(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos")
    return {"mensaje": f"Hola admin {user['username']}"}
