#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PenteIA v4.0 - E2E Screenshot Capture
Captures screenshots of all pages for validation
"""

import time
import os
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except ImportError:
    print(" Selenium no instalado. Instalando...")
    os.system("pip install selenium --quiet")
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

def take_screenshot(driver, url, filename, wait_time=3):
    """Take screenshot of a page"""
    try:
        print(f"[*] Abrindo: {url}")
        driver.get(url)
        time.sleep(wait_time)

        # Maximize window
        driver.maximize_window()

        # Take screenshot
        screenshot_path = os.path.join("screenshots", filename)
        os.makedirs("screenshots", exist_ok=True)

        driver.save_screenshot(screenshot_path)
        print(f"[OK] Screenshot salvo: {screenshot_path}")

        return True
    except Exception as e:
        print(f"[ERROR] Erro ao capturar {filename}: {str(e)}")
        return False

def main():
    print("=" * 60)
    print("PenteIA v4.0 - E2E Screenshot Capture")
    print("=" * 60)
    print()

    # Initialize Chrome driver
    print("[*] Iniciando navegador Chrome...")
    try:
        options = webdriver.ChromeOptions()
        # options.add_argument('--headless')  # Uncomment for headless mode
        options.add_argument('--disable-blink-features=AutomationControlled')
        driver = webdriver.Chrome(options=options)
    except Exception as e:
        print(f" Erro ao iniciar Chrome: {e}")
        print("   Certifique-se de ter ChromeDriver instalado")
        return

    results = []

    # Test 1: Dashboard
    print("\n[1/3] Capturando Dashboard...")
    results.append(take_screenshot(
        driver,
        "http://localhost:8000",
        "01_dashboard.png",
        wait_time=2
    ))

    # Test 2: DDoS Testing Page
    print("\n[2/3] Capturando DDoS Testing Page...")
    results.append(take_screenshot(
        driver,
        "http://localhost:8000/ddos",
        "02_ddos_page.png",
        wait_time=2
    ))

    # Test 3: API Swagger
    print("\n[3/3] Capturando API Swagger Docs...")
    results.append(take_screenshot(
        driver,
        "http://localhost:8000/docs",
        "03_api_docs.png",
        wait_time=3
    ))

    # Close driver
    driver.quit()

    # Summary
    print("\n" + "=" * 60)
    print("RESUMO DE SCREENSHOTS")
    print("=" * 60)

    tests = [
        "Dashboard Principal",
        "DDoS Testing Page",
        "API Swagger Docs"
    ]

    for i, (test, result) in enumerate(zip(tests, results), 1):
        status = " PASS" if result else " FAIL"
        print(f"[{i}] {test:30} {status}")

    passed = sum(results)
    total = len(results)

    print()
    print(f"Total: {passed}/{total} screenshots capturados com sucesso")
    print()
    print("Screenshots salvos em: ./screenshots/")
    print()
    print("=" * 60)

if __name__ == "__main__":
    main()

