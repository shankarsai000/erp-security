import pytest
import time
import socket
import threading
import uvicorn
import gateway.app as gateway_module
from backend.fake_erp import fake_erp

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="session", autouse=True)
def live_fake_erp_server():
    """Starts fake ERP backend on localhost for live proxying across test session."""
    port = get_free_port()
    config = uvicorn.Config(app=fake_erp, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    
    start_time = time.time()
    while not server.started and time.time() - start_time < 5.0:
        time.sleep(0.05)
        
    old_backend_url = gateway_module.config.backend_url
    gateway_module.config.backend_url = f"http://127.0.0.1:{port}"
    gateway_module.http_client = None
    
    yield f"http://127.0.0.1:{port}"
    
    server.should_exit = True
    gateway_module.config.backend_url = old_backend_url
    gateway_module.http_client = None
