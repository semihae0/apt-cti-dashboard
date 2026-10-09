import asyncio
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

MITRE_CACHE = []
MITRE_TECH_DETAILS = {}
MITRE_RELATIONSHIPS = {}
MISP_ACTORS_CACHE = []

COUNTRY_MAP = {
    "ru": ("Rusya", "🇷🇺"),
    "cn": ("Çin", "🇨🇳"),
    "kp": ("Kuzey Kore", "🇰🇵"),
    "ir": ("İran", "🇮🇷"),
    "us": ("Amerika Birleşik Devletleri", "🇺🇸"),
    "il": ("İsrail", "🇮🇱"),
    "vn": ("Vietnam", "🇻🇳"),
    "by": ("Belarus", "🇧🇾"),
    "tr": ("Türkiye", "🇹🇷"),
    "in": ("Hindistan", "🇮🇳"),
    "pk": ("Pakistan", "🇵🇰"),
    "ua": ("Ukrayna", "🇺🇦"),
}

async def preload_threat_data():
    global MITRE_CACHE, MITRE_TECH_DETAILS, MITRE_RELATIONSHIPS, MISP_ACTORS_CACHE
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    misp_url = "https://raw.githubusercontent.com/MISP/misp-galaxy/master/clusters/threat-actor.json"
    
    async with httpx.AsyncClient() as client:
        try:
            res_mitre = await client.get(mitre_url, timeout=40.0)
            res_mitre.raise_for_status()
            if res_mitre.status_code == 200:
                data = res_mitre.json()
                objects = data.get("objects", [])
                
                tech_details = {}
                relationships = {}
                groups = []

                for obj in objects:
                    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                        continue
                    obj_type = obj.get("type")
                    if obj_type == "intrusion-set":
                        groups.append(obj)
                    elif obj_type == "attack-pattern":
                        tid = obj.get("id")
                        tname = obj.get("name")
                        text_id = ""
                        for ref in obj.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                text_id = ref.get("external_id")
                                break
                        tactics = [
                            kc.get("phase_name", "").replace("-", " ").title()
                            for kc in obj.get("kill_chain_phases", [])
                            if kc.get("kill_chain_name") == "mitre-attack"
                        ]
                        tech_details[tid] = {
                            "tech_id": text_id,
                            "name": tname,
                            "full_label": f"{text_id} - {tname}" if text_id else tname,
                            "tactics": tactics if tactics else ["General"]
                        }
                    elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
                        src = obj.get("source_ref")
                        tgt = obj.get("target_ref")
                        if src and tgt and tgt.startswith("attack-pattern--"):
                            if src not in relationships:
                                relationships[src] = []
                            relationships[src].append(tgt)

                MITRE_CACHE = groups
                MITRE_TECH_DETAILS = tech_details
                MITRE_RELATIONSHIPS = relationships
        except Exception as exc:
            print(f"Veri yüklenemedi: {type(exc).__name__}: {exc}", flush=True)

        try:
            res_misp = await client.get(misp_url, timeout=25.0)
            res_misp.raise_for_status()
            if res_misp.status_code == 200:
                data = res_misp.json()
                MISP_ACTORS_CACHE = data.get("values", [])
        except Exception as exc:
            print(f"Veri yüklenemedi: {type(exc).__name__}: {exc}", flush=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(preload_threat_data())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

app = FastAPI(lifespan=lifespan)

@app.get("/", response_class=FileResponse)
async def home():
    return FileResponse(Path(__file__).resolve().parent / "index.html")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class SearchResult(BaseModel):
    mitre_attack: str | dict | list
    malpedia: str | dict | list
    misp_galaxy: str | dict | list

def search_mitre_memory(query: str) -> str | dict | list:
    if not MITRE_CACHE:
        return "MITRE verisi henüz hazır değil. Yükleme başarısız olmuş olabilir; terminali kontrol edin."
        
    q_lower = query.strip().casefold()
    matching_groups = []
    
    for obj in MITRE_CACHE:
        name = obj.get("name", "").casefold()
        aliases = [a.casefold() for a in obj.get("aliases", [])]
        ext_ids = [
            ref.get("external_id", "").casefold() 
            for ref in obj.get("external_references", []) 
            if ref.get("external_id")
        ]
        if q_lower in name or any(q_lower in a for a in aliases) or q_lower in ext_ids:
            g = dict(obj)
            gid = g["id"]
            
            structured_techs = []
            for t_ref in MITRE_RELATIONSHIPS.get(gid, []):
                if t_ref in MITRE_TECH_DETAILS:
                    structured_techs.append(MITRE_TECH_DETAILS[t_ref])
            
            seen = set()
            unique_techs = []
            for st in structured_techs:
                if st["tech_id"] and st["tech_id"] not in seen:
                    seen.add(st["tech_id"])
                    unique_techs.append(st)
                    
            g["structured_techniques"] = sorted(unique_techs, key=lambda x: x["tech_id"])
            g["record_created_year"] = g.get("created", "")[:4] if g.get("created") else "Bilinmiyor"
            matching_groups.append(g)

    exact_groups = [g for g in matching_groups if q_lower in
                    [g.get("name", "").casefold()] + [a.casefold() for a in g.get("aliases", [])] +
                    [r.get("external_id", "").casefold() for r in g.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"]]
    return exact_groups or matching_groups or "Herhangi bir çıktı bulunamadı."

async def search_malpedia(query: str, mitre_aliases: list) -> str | dict | list:
    base_api = "https://malpedia.caad.fkie.fraunhofer.de/api/get/actor/"
    search_terms = [query] + mitre_aliases
    seen = set()
    unique_terms = [x for x in search_terms if not (x.lower() in seen or seen.add(x.lower()))]
    
    actor_data_result = None

    async with httpx.AsyncClient() as client:
        for term in unique_terms:
            term_formatted = term.strip().replace(" ", "_").lower()
            try:
                res = await client.get(base_api + term_formatted, timeout=6.0)
                if res.status_code == 200:
                    actor_data_result = res.json()
                    break
            except Exception:
                pass
                
            try:
                res_group = await client.get(base_api + term_formatted + "_group", timeout=6.0)
                if res_group.status_code == 200:
                    actor_data_result = res_group.json()
                    break
            except Exception:
                pass

        if not actor_data_result:
            try:
                all_res = await client.get("https://malpedia.caad.fkie.fraunhofer.de/api/get/actors", timeout=8.0)
                if all_res.status_code == 200:
                    actors = all_res.json()
                    for term in unique_terms:
                        term_lower = term.lower()
                        for actor_id, a_info in actors.items():
                            name = str(a_info.get("value", "")).lower()
                            synonyms = [str(s).lower() for s in a_info.get("meta", {}).get("synonyms", [])]
                            if term_lower in actor_id.lower() or term_lower in name or term_lower in synonyms:
                                specific_res = await client.get(base_api + actor_id, timeout=6.0)
                                if specific_res.status_code == 200:
                                    actor_data_result = specific_res.json()
                                    break
                        if actor_data_result:
                            break
            except Exception:
                pass
            
    if actor_data_result and isinstance(actor_data_result, dict):
        country_code = actor_data_result.get("meta", {}).get("country", "")
        if country_code:
            c_code_clean = str(country_code).lower().strip()
            c_name, c_flag = COUNTRY_MAP.get(c_code_clean, (c_code_clean.upper(), "🌐"))
            actor_data_result["country_display"] = f"{c_flag} {c_name}"
        else:
            actor_data_result["country_display"] = "🌐 Bilinmiyor / Belirsiz"
        return actor_data_result

    return "Herhangi bir çıktı bulunamadı."

def search_misp_galaxy(query: str, aliases: list) -> str | dict | list:
    if not MISP_ACTORS_CACHE:
        return "MISP verisi henüz hazır değil. Yükleme başarısız olmuş olabilir; terminali kontrol edin."

    search_terms = [query.lower()] + [a.lower() for a in aliases]
    seen = set()
    unique_terms = [x for x in search_terms if not (x in seen or seen.add(x))]

    matched = []
    seen_actors = set()

    for item in MISP_ACTORS_CACHE:
        name = item.get("value", "").lower()
        meta = item.get("meta", {})
        synonyms = [str(s).lower() for s in meta.get("synonyms", [])]
        refs = [str(r).lower() for r in meta.get("refs", [])]

        is_match = False
        for term in unique_terms:
            if len(term) > 2 and (term in name or any(term in s for s in synonyms)):
                is_match = True
                break

        if is_match and item.get("value") not in seen_actors:
            seen_actors.add(item.get("value"))
            matched.append({
                "name": item.get("value"),
                "description": item.get("description", "Açıklama bulunmuyor."),
                "synonyms": meta.get("synonyms", []),
                "country": meta.get("country", ""),
                "cfr_target_category": meta.get("cfr-target-category", []),
                "cfr_suspected_state_sponsor": meta.get("cfr-suspected-state-sponsor", "")
            })


    return matched if matched else "Herhangi bir çıktı bulunamadı."

@app.get("/api/search", response_model=SearchResult)
async def perform_search(q: str):
    q = q.strip()
    if not q or len(q) > 120:
        raise HTTPException(status_code=422, detail="Sorgu 1–120 karakter olmalı.")
    mitre_res = search_mitre_memory(q)
    
    mitre_aliases = []
    if isinstance(mitre_res, list) and len(mitre_res) == 1:
        for item in mitre_res:
            if item.get("name"):
                mitre_aliases.append(item.get("name"))
            if item.get("aliases"):
                mitre_aliases.extend(item.get("aliases"))

    if isinstance(mitre_res, list) and len(mitre_res) > 1:
        malpedia_res = misp_res = "Birden fazla MITRE aktörü bulundu. Tam aktör adını veya G kimliğini kullanın."
    else:
        misp_res = search_misp_galaxy(q, mitre_aliases)
        try:
            malpedia_res = await asyncio.wait_for(search_malpedia(q, mitre_aliases), timeout=12.0)
        except asyncio.TimeoutError:
            malpedia_res = "Malpedia zaman aşımına uğradı. Diğer kaynakların sonuçları aşağıda gösteriliyor."

    
    return SearchResult(
        mitre_attack=mitre_res,
        malpedia=malpedia_res,
        misp_galaxy=misp_res
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
