"""Запуск панели: python run.py"""
import uvicorn

from app.config import BASE_PATH, HOST, PORT

if __name__ == "__main__":
    print(f"Panel: http://{HOST}:{PORT}{BASE_PATH}/")
    # workers=1 обязательно: фоновый воркер синхронизации живёт в процессе приложения
    uvicorn.run("app.main:app", host=HOST, port=PORT, workers=1, proxy_headers=False,
                server_header=False, log_level="info")
