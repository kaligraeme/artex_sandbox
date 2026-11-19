"""Build the standalone lab diagram from the checked-in Compose topology."""
from pathlib import Path
from html import escape

OUT = Path(__file__).resolve().parents[1] / "assets" / "artex-lab-architecture.svg"
s = []
def add(v): s.append(v)
def rect(x,y,w,h,fill,stroke="#cbd5e1",dash=None,r=16):
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="2"'+(f' stroke-dasharray="{dash}"' if dash else '')+'/>')
def text(x,y,t,size=20,color="#163047",weight=400):
    add(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}">{escape(t)}</text>')
def path(d,color="#147d92",dash=None,end=True,width=3):
    add(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"'+(f' stroke-dasharray="{dash}"' if dash else '')+(f' marker-end="url(#{ {"#147d92":"request", "#8b5ab5":"model", "#d19a24":"telemetry", "#c45064":"revoke", "#64748b":"state"}[color]})"' if end else '')+'/>')
def card(x,y,w,h,title,lines,accent="#147d92"):
    rect(x,y,w,h,"#ffffff",accent,r=12)
    text(x+20,y+34,title,24,weight=700)
    for i,line in enumerate(lines): text(x+20,y+63+i*24,line,18,"#526579")

add('<svg xmlns="http://www.w3.org/2000/svg" width="1800" height="1220" viewBox="0 0 1800 1220" role="img" aria-labelledby="title desc">')
add('<title id="title">ARTEX local lab architecture</title><desc id="desc">Windows host with local LM Studio and Docker Desktop. ARTEX reaches the WAF through ingress_net, PostgreSQL through db_net, and the local model through the host gateway. The WAF routes every target API request over proxy_net. All four target services send telemetry to the defender through control_net; the defender revokes runs at identity, workflow and records.</desc>')
add('<defs>')
for name,color in [('request','#147d92'),('model','#8b5ab5'),('telemetry','#d19a24'),('revoke','#c45064'),('state','#64748b')]:
    add(f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="{color}"/></marker>')
add('</defs><g font-family="Segoe UI, Arial, sans-serif">')
rect(0,0,1800,1220,"#f7f9fc","#f7f9fc",r=0)
text(55,62,"ARTEX  /  LOCAL LAB ARCHITECTURE",36,weight=750)
text(55,99,"One workstation. Four network boundaries. A synthetic API chain with live prevention and response.",22,"#526579")
rect(40,127,1720,947,"#ffffff","#a8b8c8",r=22)
text(65,161,"WINDOWS HOST",17,"#526579",700)
card(80,185,470,112,"Operator / browser",["ARTEX UI :8787  ·  Traffic proxy :8788","WAF test endpoint :8080"],"#64748b")
card(715,185,470,112,"LM Studio  ·  local model",["OpenAI-compatible API :1234/v1","Runs on the host, outside Docker"],"#8b5ab5")
text(1230,213,"HOST ACCESS",16,"#526579",700)
text(1230,242,"Published ports default to 0.0.0.0",19)
text(1230,270,"ARTEX_BIND_ADDR / WAF_BIND_ADDR",17,"#526579")
text(1230,294,"can restrict their listen address.",17,"#526579")

rect(65,330,1670,720,"#f3f6fa","#8098ad","10 6",20)
text(800,363,"DOCKER DESKTOP / WSL 2  ·  CONTAINER BOUNDARY",18,"#526579",700)

rect(85,390,590,258,"#edf7fa","#70adba",r=16)
text(105,422,"01  INGRESS NETWORK",20,"#166579",700)
text(105,445,"ingress_net  ·  host-routable bridge",17,"#526579")
card(105,490,230,125,"ARTEX agent",["Planner / Worker","Bounded API task"],"#147d92")
card(425,490,230,125,"WAF / proxy",["Nginx + ModSecurity","OWASP CRS · :8080","Rule 99001 · patch"],"#147d92")
path('M335 551H425')
text(349,538,"HTTP",16,"#147d92",600)
text(350,638,"No direct target access",17,"#526579")

rect(715,390,1000,274,"#edf7f1","#83b59b",r=16)
text(735,422,"02  TARGET APPLICATION NETWORK",20,"#286747",700)
text(735,447,"proxy_net  ·  internal  ·  WAF + four target services",17,"#526579")
path('M655 520H695V473H1570',end=False)
for x in [740,980,1220,1460]: path(f'M{x+110} 473V505')
for x,title,lines in [
    (740,"1  Edge",["Mock token export","/api/edge/export"]),
    (980,"2  Identity",["Token exchange","/api/identity/exchange"]),
    (1220,"3  Workflow",["Service pivot","/api/workflow/pivot"]),
    (1460,"4  Records",["Synthetic canary","/api/records/canary"])]:
    card(x,505,220,110,title,lines,"#3d8c65")
text(735,487,"Target APIs · :8000",15,"#286747")

# Model route is bidirectional in use; the arrow identifies the initiating client.
path('M310 490V465H620V315H950V297',"#8b5ab5","7 5")
text(80,320,"Local inference via host.docker.internal:1234",17,"#8b5ab5",600)

rect(85,738,590,287,"#f0f3f8","#97a7bd",r=16)
text(145,773,"03  AGENT STATE NETWORK",20,"#526579",700)
text(145,799,"db_net  ·  internal  ·  ARTEX + PostgreSQL",17,"#526579")
card(145,851,350,112,"PostgreSQL 16",["ARTEX state store · :5432","Persistent volume: pgdata"],"#64748b")
path('M125 615V907H145',"#64748b")
text(145,703,"Agent state / SQL",18,"#64748b",600)
text(145,1002,"Stores agent state; separate from the synthetic records target.",17,"#526579")

rect(715,684,1000,341,"#fffbef","#c6ad6c",r=16)
text(735,911,"04  DEFENSE / CONTROL",20,"#8b6518",700)
text(735,941,"control_net  ·  internal",17,"#526579")
text(735,966,"Four targets + defender",17,"#526579")
# Common telemetry bus from every target, terminating at the defender.
for x in [805,1045,1285,1525]: path(f'M{x} 615V772',"#d19a24",end=False)
path('M805 772H1525',"#d19a24",end=False)
path('M1010 772V859H1100',"#d19a24")
text(745,810,"Events from all four services",18,"#9a721d",600)
text(745,835,"POST /ingest · correlated run_id",17,"#526579")
card(1100,837,340,136,"ML defender",["IsolationForest + response rules","Receives telemetry on :9000","Revokes the synthetic run_id"],"#b0872b")
# The return channel terminates at each protected service, not at edge.
path('M1440 909H1675V792H1120',"#c45064","6 5",end=False)
for x in [1120,1360,1600]: path(f'M{x} 792V615',"#c45064","6 5")
text(1470,865,"Active response",18,"#c45064",600)
text(1470,890,"POST /internal/revoke",17,"#c45064")
text(735,1002,"No backend host ports. Telemetry and revocation are best-effort; targets enforce revocation.",17,"#526579")

# Compact footer: legend and the distinction between logical steps and network hops.
for x,color,label,dash in [(65,"#147d92","API requests",None),(345,"#8b5ab5","Local model","7 5"),(635,"#64748b","Agent state",None),(920,"#d19a24","Telemetry",None),(1190,"#c45064","Revocation","6 5")]:
    path(f'M{x} 1110H{x+52}',color,dash)
    text(x+65,1117,label,19,"#526579")
text(65,1160,"READING THE MAP",17,"#163047",700)
text(275,1160,"Every API hop goes through the WAF. Steps 1 → 4 show the logical token sequence.",20,"#526579")
text(65,1195,"Source: checked-in Docker Compose + WAF routes. Configuration view; not a live deployment attestation.",17,"#718096")
add('</g></svg>')
OUT.write_text('\n'.join(s),encoding='utf-8')
print(OUT)
