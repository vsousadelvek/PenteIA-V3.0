import sys, uuid, json
from datetime import datetime
sys.path.insert(0, 'E:/cyber/PenteIA-V4.0')
from database import SessionLocal
from models import Simulation

USER_ID = 'bd7e7dd9-7ab6-4b6d-8dec-c60cb62a8fce'
db = SessionLocal()

techniques = [
    {'id':'T1190','name':'Injecao SQL','status':'found','cvss_severity':'Critical','cvss_score':9.8,'detail':'SQLi bypass via OR 1=1 — acesso ao banco de dados','compliance':['OWASP A03','PCI DSS 6.5.1']},
    {'id':'T1190b','name':'SQLi com Disfarce','status':'found','cvss_severity':'Critical','cvss_score':9.1,'detail':'Bypass de filtro com double-encoding %27','compliance':['OWASP A03']},
    {'id':'T1059','name':'Cross-Site Scripting','status':'found','cvss_severity':'High','cvss_score':7.5,'detail':'XSS refletido no campo de busca da aplicacao','compliance':['OWASP A03','PCI DSS 6.5.7']},
    {'id':'T1083','name':'Acesso a Arquivos Internos','status':'found','cvss_severity':'High','cvss_score':7.2,'detail':'Path traversal via ../etc/passwd funcionou','compliance':['OWASP A01']},
    {'id':'T1590','name':'Fingerprint do Servidor','status':'found','cvss_severity':'Medium','cvss_score':5.3,'detail':'Server: nginx/1.18.0 Ubuntu revelado no header','compliance':['CIS 9.1']},
    {'id':'T1592','name':'Cabecalhos de Seguranca HTTP','status':'found','cvss_severity':'Medium','cvss_score':4.8,'detail':'Faltam X-Frame-Options, CSP, HSTS','compliance':['OWASP A05','CIS 9.4']},
    {'id':'T1499','name':'Rate Limiting','status':'found','cvss_severity':'Medium','cvss_score':5.0,'detail':'Sem limite de requisicoes por IP detectado','compliance':['OWASP A04']},
    {'id':'T1078','name':'Autenticacao JWT','status':'blocked','cvss_severity':'High','cvss_score':8.1,'detail':'Token invalido rejeitado corretamente com 401','compliance':['OWASP A07']},
    {'id':'T1110','name':'Senhas Padrao','status':'blocked','cvss_severity':'Critical','cvss_score':9.1,'detail':'Login admin/admin e root/123 bloqueados','compliance':['CIS 5.1']},
    {'id':'T1595','name':'Bloqueio de Scanners','status':'blocked','cvss_severity':'High','cvss_score':7.0,'detail':'sqlmap, nikto e acunetix detectados e bloqueados (403)','compliance':['CIS 9.2']},
    {'id':'T1087','name':'Endpoints de API','status':'blocked','cvss_severity':'Medium','cvss_score':6.1,'detail':'Rotas /api/* exigem autenticacao JWT valida','compliance':['OWASP A01']},
    {'id':'T1190c','name':'JWT algoritmo none','status':'blocked','cvss_severity':'Critical','cvss_score':9.3,'detail':'Algoritmo none rejeitado corretamente pelo servidor','compliance':['OWASP A02']},
    {'id':'T1087b','name':'Arquivos Sensiveis Expostos','status':'blocked','cvss_severity':'High','cvss_score':7.8,'detail':'.git, .env, backup.zip bloqueados (403)','compliance':['OWASP A05']},
]

found = [t for t in techniques if t['status'] == 'found']
blocked = [t for t in techniques if t['status'] == 'blocked']
vuln_cvss = sum(t['cvss_score'] for t in found)
total_cvss = sum(t['cvss_score'] for t in techniques)
score = round((vuln_cvss / total_cvss) * 100, 1) if total_cvss else 0

from models import Playbook
pb = db.query(Playbook).first()
if not pb:
    pb = Playbook(
        id=str(uuid.uuid4()),
        user_id=USER_ID,
        name='Web Application Full Audit',
        techniques=len(techniques),
        severity='Critical',
        description='Auditoria completa de aplicacao web',
    )
    db.add(pb); db.flush()

sim = Simulation(
    id=str(uuid.uuid4()),
    user_id=USER_ID,
    playbook_id=pb.id,
    target='localhost:9090',
    status='completed',
    score=score,
    results={'techniques': techniques},
)
db.add(sim)
db.commit()
print(f"Simulacao inserida OK")
print(f"Score: {score}%")
print(f"Vulneraveis: {len(found)} | Protegidos: {len(blocked)}")
db.close()
