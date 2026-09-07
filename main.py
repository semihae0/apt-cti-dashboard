from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class SearchResult(BaseModel):
    mitre_attack: str | dict | list
    malpedia: str | dict | list


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

async def search_mitre(query: str) -> str | dict | list:
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=20.0)
            if response.status_code == 200:
                data = response.json()
                objects = data.get("objects", [])
                
                matching_groups = []
                q_lower = query.lower()
                for obj in objects:
                    if obj.get("type") == "intrusion-set":
                        name = obj.get("name", "").lower()
                        aliases = [a.lower() for a in obj.get("aliases", [])]
                        ext_ids = [
                            ref.get("external_id", "").lower() 
                            for ref in obj.get("external_references", []) 
                            if ref.get("external_id")
                        ]
                        if q_lower in name or q_lower in aliases or q_lower in ext_ids:
                            matching_groups.append(obj)
                
                if not matching_groups:
                    return "Herhangi bir çıktı bulunamadı."

                group_ids = {g["id"] for g in matching_groups}
                group_to_tech = {gid: [] for gid in group_ids}
                
                for obj in objects:
                    if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                        src = obj.get("source_ref")
                        tgt = obj.get("target_ref")
                        if src in group_ids and tgt and tgt.startswith("attack-pattern--"):
                            group_to_tech[src].append(tgt)

                
                tech_details = {}
                for obj in objects:
                    if obj.get("type") == "attack-pattern":
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

                for g in matching_groups:
                    gid = g["id"]
                    structured_techs = []
                    for t_ref in group_to_tech.get(gid, []):
                        if t_ref in tech_details:
                            structured_techs.append(tech_details[t_ref])
                    
                    
                    seen = set()
                    unique_techs = []
                    for st in structured_techs:
                        if st["tech_id"] and st["tech_id"] not in seen:
                            seen.add(st["tech_id"])
                            unique_techs.append(st)
                    
                    g["structured_techniques"] = sorted(unique_techs, key=lambda x: x["tech_id"])
                    
                    g["first_seen_year"] = g.get("created", "")[:4] if g.get("created") else "Bilinmiyor"

                return matching_groups
            return "Herhangi bir çıktı bulunamadı."
        except Exception:
            return "Herhangi bir çıktı bulunamadı."

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
                res = await client.get(base_api + term_formatted, timeout=10.0)
                if res.status_code == 200:
                    actor_data_result = res.json()
                    break
            except Exception:
                pass
                
            try:
                res_group = await client.get(base_api + term_formatted + "_group", timeout=10.0)
                if res_group.status_code == 200:
                    actor_data_result = res_group.json()
                    break
            except Exception:
                pass

        if not actor_data_result:
            try:
                all_res = await client.get("https://malpedia.caad.fkie.fraunhofer.de/api/get/actors", timeout=15.0)
                if all_res.status_code == 200:
                    actors = all_res.json()
                    for term in unique_terms:
                        term_lower = term.lower()
                        for actor_id, a_info in actors.items():
                            name = str(a_info.get("value", "")).lower()
                            synonyms = [str(s).lower() for s in a_info.get("meta", {}).get("synonyms", [])]
                            if term_lower in actor_id.lower() or term_lower in name or term_lower in synonyms:
                                specific_res = await client.get(base_api + actor_id, timeout=10.0)
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

@app.get("/api/search", response_model=SearchResult)
async def perform_search(q: str):
    mitre_res = await search_mitre(q)
    
    mitre_aliases = []
    if isinstance(mitre_res, list):
        for item in mitre_res:
            if item.get("name"):
                mitre_aliases.append(item.get("name"))
            if item.get("aliases"):
                mitre_aliases.extend(item.get("aliases"))
                
    malpedia_res = await search_malpedia(q, mitre_aliases)
    
    return SearchResult(
        mitre_attack=mitre_res,
        malpedia=malpedia_res
    )