#!/usr/bin/env python3
"""
CLVX - Cloud & Firewall Evasion Framework
Console interativo estilo msfconsole.

Comandos:
  show modules            lista módulos disponíveis
  use <modulo>            seleciona um módulo (ex: use evade/detect)
  show options            mostra opções do módulo selecionado
  set <OPCAO> <valor>     define uma opção
  run                     executa o módulo selecionado
  show findings           mostra todos os findings acumulados na sessão
  save report <arquivo>   salva os findings acumulados em JSON
  back                    sai do módulo atual
  help                    mostra esta ajuda
  exit / quit             sai do console
"""

import sys
import json
import shlex
import time

from utils.colors import Colors
from modules.evade_detect import WAFDetector
from modules.cloud_cloudflare import CloudflareBypass
from modules.cloud_azure import AzureRecon
from modules.firewall_portscan import FirewallPortScan

VERSION = "2.0.0"

MODULE_REGISTRY = {
    "evade/detect":       WAFDetector,
    "cloud/cloudflare":   CloudflareBypass,
    "cloud/azure":        AzureRecon,
    "firewall/portscan":  FirewallPortScan,
}

BANNER = r"""
   ______ __    _    ____  __
  / ____// /   | |  / /\ \/ /
 / /    / /    | | / /  \  /
/ /___ / /___  | |/ /   / /
\____//_____/  |___/   /_/    Cloud & Firewall Evasion Framework
                               v{version} — console interativo
"""

DISCLAIMER = """
[!] USO RESTRITO A TESTES AUTORIZADOS
    Use apenas em ambientes que você tem autorização explícita para testar
    (labs próprios, CTFs, labs de certificação, engajamentos com escopo
    assinado). Vários módulos fazem requisições ativas contra o alvo
    (probing de WAF, enumeração de containers, ACK probe). Rodar isso
    contra infraestrutura de terceiros sem autorização é crime.
"""


class Console:
    def __init__(self):
        self.current_module = None
        self.current_name = None
        self.session_findings = []

    def run(self):
        print(BANNER.format(version=VERSION))
        print(DISCLAIMER)
        while True:
            prompt = f"clvx ({self.current_name}) > " if self.current_name else "clvx > "
            try:
                line = input(f"{Colors.BOLD}{Colors.GREEN}{prompt}{Colors.RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Saindo.")
                break
            if not line:
                continue
            self.dispatch(line)

    def dispatch(self, line: str):
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"[-] Erro de sintaxe: {e}")
            return
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("exit", "quit"):
            sys.exit(0)
        elif cmd == "help":
            print(__doc__)
        elif cmd == "show" and args and args[0] == "modules":
            self._show_modules()
        elif cmd == "show" and args and args[0] == "options":
            self._show_options()
        elif cmd == "show" and args and args[0] == "findings":
            self._show_findings()
        elif cmd == "use":
            self._use_module(args)
        elif cmd == "set":
            self._set_option(args)
        elif cmd == "run":
            self._run_module()
        elif cmd == "back":
            self.current_module = None
            self.current_name = None
        elif cmd == "save" and len(args) >= 2 and args[0] == "report":
            self._save_report(args[1])
        else:
            print(f"[-] Comando desconhecido: '{line}'. Digite 'help'.")

    def _show_modules(self):
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Módulos disponíveis:{Colors.RESET}\n")
        for name, cls in MODULE_REGISTRY.items():
            print(f"    {Colors.CYAN}{name:<22}{Colors.RESET}{cls.DESCRIPTION}")
        print()

    def _use_module(self, args):
        if not args:
            print("[-] Uso: use <modulo> (ex: use evade/detect)")
            return
        name = args[0]
        cls = MODULE_REGISTRY.get(name)
        if not cls:
            print(f"[-] Módulo não encontrado: {name}. Veja 'show modules'.")
            return
        self.current_module = cls()
        self.current_name = name
        print(f"[*] Módulo selecionado: {name}")

    def _show_options(self):
        if not self.current_module:
            print("[-] Nenhum módulo selecionado. Use 'use <modulo>' primeiro.")
            return
        self.current_module.show_options()

    def _set_option(self, args):
        if not self.current_module:
            print("[-] Nenhum módulo selecionado.")
            return
        if len(args) < 2:
            print("[-] Uso: set <OPCAO> <valor>")
            return
        name, value = args[0], " ".join(args[1:])
        try:
            self.current_module.set_option(name, value)
            print(f"[*] {name.upper()} => {value}")
        except KeyError as e:
            print(f"[-] {e}")

    def _run_module(self):
        if not self.current_module:
            print("[-] Nenhum módulo selecionado.")
            return
        try:
            findings = self.current_module.run()
            self.session_findings.extend(findings or [])
        except KeyboardInterrupt:
            print("\n[!] Interrompido pelo usuário.")
        except Exception as e:
            print(f"[-] Erro ao executar módulo: {e}")

    def _show_findings(self):
        if not self.session_findings:
            print("[*] Nenhum finding acumulado nesta sessão ainda.")
            return
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Findings da sessão ({len(self.session_findings)}):{Colors.RESET}\n")
        sev_color = {"CRITICAL": Colors.RED, "HIGH": Colors.RED, "MEDIUM": Colors.YELLOW, "INFO": Colors.CYAN, "LOW": Colors.DARK_GRAY}
        for f in self.session_findings:
            color = sev_color.get(f["severity"], Colors.WHITE)
            print(f"  {color}[{f['severity']:<8}]{Colors.RESET} {f['check']:<40} {Colors.DARK_GRAY}{f['target']}{Colors.RESET}")
        print()

    def _save_report(self, filename: str):
        if not filename.endswith(".json"):
            filename += ".json"
        try:
            with open(filename, "w") as fh:
                json.dump({
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "findings": self.session_findings,
                }, fh, indent=2)
            print(f"[+] Relatório salvo em {filename} ({len(self.session_findings)} findings)")
        except OSError as e:
            print(f"[-] Falha ao salvar relatório: {e}")


if __name__ == "__main__":
    Console().run()
