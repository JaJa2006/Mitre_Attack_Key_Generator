import streamlit as st
import pandas as pd
import json
import requests
from io import BytesIO

# function to load ATT&CK data
def load_attack(domain_name, stix_data, matrix_data, kill_chain_key):

    # extract matrix order
    tactic_order = []
    for obj in matrix_data.get("objects", []):
        if obj.get("type") == "x-mitre-matrix":
            tactic_order = obj.get("tactic_refs", [])
            break

    tactics_by_id = {}
    tactics_by_shortname = {}

    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            stix_id = obj.get("id")
            short = obj.get("x_mitre_shortname")
            name = obj.get("name", "")

            code = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    code = ref.get("external_id", "")
                    break

            tactics_by_id[stix_id] = {
                "shortname": short,
                "tactic_name": name,
                "tactic_id": code,
            }
            tactics_by_shortname[short] = {
                "tactic_name": name,
                "tactic_id": code,
            }

    rows = []

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if domain_name not in obj.get("x_mitre_domains", []):
            continue

        tech_code = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_code = ref.get("external_id", "")
                break
        if not tech_code or "." in tech_code:
            continue

        tech_name = obj.get("name", "")

        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") in kill_chain_key:
                short = phase.get("phase_name")
                t = tactics_by_shortname.get(short)
                if t:
                    rows.append({
                        "tactic_name": t["tactic_name"],
                        "tactic_id": t["tactic_id"],
                        "technique_name": tech_name,
                        "technique_id": tech_code
                    })

        for short in obj.get("x_mitre_tactics", []):
            t = tactics_by_shortname.get(short)
            if t:
                rows.append({
                    "tactic_name": t["tactic_name"],
                    "tactic_id": t["tactic_id"],
                    "technique_name": tech_name,
                    "technique_id": tech_code
                })

    df = pd.DataFrame(rows).drop_duplicates().reset_index(drop=True)

    # sort order
    tactic_sort_order = {}
    for i, tac_id in enumerate(tactic_order):
        if tac_id in tactics_by_id:
            tactic_sort_order[tactics_by_id[tac_id]["tactic_name"]] = i

    df["tactic_sort"] = df["tactic_name"].map(tactic_sort_order)
    df = df.sort_values(by=["tactic_sort", "technique_name"]).drop(columns=["tactic_sort"])
    df = df.reset_index(drop=True)
    return df



# streamlit app
st.title("MITRE ATT&CK Key Generator")

st.write("""
Enter only the JSON **filenames**.  

### Useful Links to File Lists
- **Enterprise STIX data:** https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack  
- **Enterprise Matrix files:** https://github.com/mitre/cti/tree/master/enterprise-attack/x-mitre-matrix  
- **ICS STIX data:** https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack  
- **ICS Matrix files:** https://github.com/mitre/cti/tree/master/ics-attack/x-mitre-matrix  
""")

st.subheader("Enterprise Files")
ent_stix_file = st.text_input("Enterprise STIX filename (example: enterprise-attack-18.1.json)")
ent_matrix_file = st.text_input("Enterprise Matrix filename (example: x-mitre-matrix--eafc1b4c.json)")

st.subheader("ICS Files")
ics_stix_file = st.text_input("ICS STIX filename (example: ics-attack-18.1.json)")
ics_matrix_file = st.text_input("ICS Matrix filename (example: x-mitre-matrix--575f48f4.json)")


# URLs
ENT_STIX_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
ICS_STIX_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/"
ENT_MATRIX_BASE = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/x-mitre-matrix/"
ICS_MATRIX_BASE = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/x-mitre-matrix/"


def fetch_json_or_error(url, label):
    """Attempt to retrieve JSON; if fails, display a friendly error."""
    try:
        resp = requests.get(url)
        if resp.status_code != 200:
            st.error(f"{label} file not found at URL:\n{url}")
            return None
        return resp.json()
    except Exception:
        st.error(f"Failed to fetch {label}. Check filename or network.")
        return None


# validate input and process
if st.button("Process ATT&CK Data"):

    # ensure filenames provided
    if not all([ent_stix_file, ent_matrix_file, ics_stix_file, ics_matrix_file]):
        st.error("All four filenames are required.")
        st.stop()

    # construct URLs
    ent_stix_url = ENT_STIX_BASE + ent_stix_file
    ent_matrix_url = ENT_MATRIX_BASE + ent_matrix_file
    ics_stix_url = ICS_STIX_BASE + ics_stix_file
    ics_matrix_url = ICS_MATRIX_BASE + ics_matrix_file

    # validate & fetch JSON safely
    ent_stix_data = fetch_json_or_error(ent_stix_url, "Enterprise STIX")
    ent_matrix_data = fetch_json_or_error(ent_matrix_url, "Enterprise Matrix")
    ics_stix_data = fetch_json_or_error(ics_stix_url, "ICS STIX")
    ics_matrix_data = fetch_json_or_error(ics_matrix_url, "ICS Matrix")

    # stop if any file failed validation
    if None in [ent_stix_data, ent_matrix_data, ics_stix_data, ics_matrix_data]:
        st.stop()

    # get data
    enterprise_df = load_attack(
        "enterprise-attack",
        ent_stix_data,
        ent_matrix_data,
        ("mitre-attack", "mitre-enterprise-attack")
    )
    enterprise_df["ENT/ICS"] = "ENT"

    ics_df = load_attack(
        "ics-attack",
        ics_stix_data,
        ics_matrix_data,
        ("mitre-attack", "mitre-ics-attack")
    )
    ics_df["ENT/ICS"] = "ICS"

    combined_df = pd.concat([enterprise_df, ics_df], ignore_index=True)

    # modify and reorder the data to format it properly
    combined_df['TT_Key'] = combined_df['ENT/ICS'] + combined_df['tactic_name'] + combined_df['technique_name']
    combined_df['Tactics With Code'] = combined_df['tactic_name'] + " (" + combined_df['tactic_id'] + ")"
    combined_df['Techniques With Code'] = combined_df['technique_name'] + " (" + combined_df['technique_id'] + ")"

    unique_tactics = combined_df[['Tactics With Code']].drop_duplicates().reset_index(drop=True)
    unique_tactics['Tactics_Order'] = range(1, len(unique_tactics) + 1)
    combined_df = combined_df.merge(unique_tactics, on='Tactics With Code', how='left')

    combined_df['Techniques_Order'] = combined_df.groupby('Tactics With Code').cumcount() + 1

    combined_df = combined_df[[
        "TT_Key",
        "ENT/ICS",
        "tactic_name",
        "technique_name",
        "Tactics_Order",
        "Techniques_Order",
        "tactic_id",
        "technique_id",
        "Tactics With Code",
        "Techniques With Code"
    ]].rename(columns={
        "tactic_name": "Tactics",
        "technique_name": "Techniques",
        "tactic_id": "Tactics Code",
        "technique_id": "Techniques Code"
    })

    # display and allow download
    st.subheader("Combined ATT&CK Matrix")
    st.dataframe(combined_df)

    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        combined_df.to_excel(writer, index=False, sheet_name="Mitre Att&ck Matrix Key")

    st.download_button(
        "Download Excel File",
        output.getvalue(),
        "Mitre Att&ck Matrix Key.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
