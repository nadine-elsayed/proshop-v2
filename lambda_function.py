import os
import json
import boto3
import pg8000.native
import requests
import google.auth.transport.requests
import google.oauth2.id_token
import logging
import traceback
from urllib3.exceptions import InsecureRequestWarning
from typing import List, Dict, Any, Tuple

# ─────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────

# Suppress SSL warnings (for internal HTTPS endpoints)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ─────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────

def make_authorized_get_request(audience: str) -> str:
    """Fetch a Google ID token for the given Cloud Run audience."""
    auth_req = google.auth.transport.requests.Request()
    return google.oauth2.id_token.fetch_id_token(auth_req, audience)


def get_secret(secret_name: str) -> dict:
    """Retrieve and parse a secret from AWS Secrets Manager."""
    client = boto3.client("secretsmanager")
    secret = client.get_secret_value(SecretId=secret_name)
    return json.loads(secret["SecretString"])


def get_db_connection(rds_secret: dict, host: str, port: int, dbname: str):
    """Establish a PostgreSQL connection using pg8000."""
    return pg8000.native.Connection(
        user=rds_secret["username"],
        password=rds_secret["password"],
        host=host,
        port=port,
        database=dbname,
    )


def fetch_tickets(conn) -> List[Dict[str, Any]]:
    """
    Fetch unprocessed tickets from the database.
    Returns a list of ticket JSON dictionaries.
    """
    query = """
    SELECT row_to_json(t)
FROM (
    SELECT
        tk."Id",
        tk."TicketNumber" AS "Ticketnr+",
        tk."Status",
        tk."CustomerNumber" AS "CCB_MainCustNo",
        tk."Anschlusskennung" AS "Anschlussk.+",
        tk."ZusAnschlusskennung" AS "zus. Anschlussk.",
        p."Name" AS "Dienst/Produkt",
        tk."KfmProdukt" AS "kaufm. Produkt",
        tk."KfmService" AS "kaufm. Service",
        tk."DienstTechnik" AS "Dienst/Technik",
        tk."ProblemBeschreibung" AS "Problembeschr",
        tk."ExakteProblemBeschreibung" AS "exakte Problem.",
        tk."LoesungBeschreibung" AS "Lösungsbeschreibung",
        tk."Verursacher",
        tk."Ort" AS "Ort+",
        to_char(tk."CreatedOn", 'DD.MM.YYYY HH24:MI:SS') AS "erfasst am",
        tk."IsDeleted" AS "isDeleted",
        (
            SELECT json_agg(
                concat_ws(
                    ' - ',
                    to_char(bl."Date", 'DD.MM.YYYY HH24:MI:SS'),
                    bl."Category",
                    bl."Text"
                )
                ORDER BY bl."Date" ASC
            )
            FROM "TicketsBLogs" bl
            WHERE bl."TicketId" = tk."Id"
        ) AS "BearbLog"
    FROM "Tickets" tk
    LEFT JOIN "Products" p ON tk."ProductId" = p."Id"
    WHERE tk."TicketNumber" IN (
        'TA0000015013148',
        'TA0000015013149',
        'TA0000015013150'
        
    )
) t;
    """
    result = conn.run(query)
    # Extract the JSON object from the list-of-lists format: [[{...}], [{...}]] -> [{...}, {...}]
    tickets = [row[0] for row in result if row and len(row) > 0 and isinstance(row[0], dict)]
    logger.info(f"📥 Fetched {len(tickets)} tickets from DB")
    return tickets


def insert_response(conn, ticket_number: str, response: dict):
    """Insert the full GenAI JSON response into the database."""
    query = """
        INSERT INTO public."GenAIResponses"
        ("Id", "TicketNumber", "Response", "Comment", "Type", "IsDeleted", "CreatedOn", "ModifiedOn", "CreatedBy", "ModifiedBy")
        VALUES (
            gen_random_uuid(),
            :ticket_number,
            :response_json::jsonb,
            NULL, 
            'Summarization',
            false,
            NOW(),
            NOW(),
            '00000000-0000-0000-0000-000000000000',
            '00000000-0000-0000-0000-000000000000'
        );
    """

    if not ticket_number:
        logger.error("❌ insert_response skipped: Missing ticket_number")
        return

    if not isinstance(response, dict):
        logger.error(f"❌ insert_response skipped for {ticket_number}: response is not a dict ({type(response)})")
        return

    try:
        response_json = json.dumps(response, ensure_ascii=False) 
        logger.info(f"[DB-INSERT] 📝 Full Response JSON for ticket {ticket_number}: {response_json}")    
    except Exception as e:
        logger.error(f"❌ Failed to serialize response for ticket {ticket_number}: {e}\n{traceback.format_exc()}")
        return

    try:
        conn.run(query, ticket_number=str(ticket_number), response_json=response_json)
        logger.info(f"[DB-INSERT] ✅ Insert succeeded for ticket={ticket_number}")
    except Exception as e:
        logger.error(f"❌ insert_response failed for {ticket_number}: {e}\n{traceback.format_exc()}")
        raise


def mark_ticket_processed(conn, ticket_id: str):
    """Mark ticket as processed in the database."""
    query = """
        UPDATE public."TicketsBLogs"
        SET "IsDeleted" = true
        WHERE "Id" = :ticket_id;
    """

    if not ticket_id:
        logger.error("❌ mark_ticket_processed skipped: missing ticket_id")
        return

    try:
        logger.info(f"[DB-UPDATE] Marking ticket {ticket_id} as processed")
        conn.run(query, ticket_id=str(ticket_id))
        logger.info(f"[DB-UPDATE] ✅ Ticket {ticket_id} marked as processed")
    except Exception as e:
        logger.error(f"❌ mark_ticket_processed failed for {ticket_id}: {e}\n{traceback.format_exc()}")
        raise


def get_iap_token(client_id: str) -> str:
    """Fetch an IAP access token for authentication."""
    return google.oauth2.id_token.fetch_id_token(
        google.auth.transport.requests.Request(), client_id
    )

# ─────────────────────────────────────────────
# Batch Processing Core (UPDATED)
# ─────────────────────────────────────────────

def process_ticket_batch(
    conn, 
    tickets: List[Dict[str, Any]], 
    llm_proxy_url: str, 
    app_method: str, 
    headers: Dict[str, str]
) -> int:
    """
    Sends a batch of tickets to the LLM service, extracts the 'results' list, 
    and processes each response based on its status.
    """
    
    # 1. Prepare the batch payload
    ticket_map = {}
    ticket_jsons_for_payload = []
    for i, ticket_json in enumerate(tickets):
        ticket_id = ticket_json.get("Id")
        ticket_number = ticket_json.get("Ticketnr+")
        if ticket_id and ticket_number:
            ticket_jsons_for_payload.append(ticket_json)
            # Map by the index in the payload list for easier lookup later
            ticket_map[len(ticket_jsons_for_payload) - 1] = {
                "id": ticket_id,
                "number": ticket_number,
                "json": ticket_json
            }
        else:
            logger.warning(f"⚠️ Skipping ticket missing Id or Ticketnr+: {ticket_json}")

    if not ticket_jsons_for_payload:
        logger.info("No valid tickets to send in batch.")
        return 0

    payload = {"ticket_description": ticket_jsons_for_payload}
    pretty_payload = json.dumps(payload, ensure_ascii=False, indent=2)
    logger.info(f"🚀 Sending batch of {len(ticket_jsons_for_payload)} tickets.")
    logger.info(f"[GCP-REQUEST] 📤 Sending full batch payload:\n{pretty_payload}")

    processed_count = 0
    
    try:
        # 2. Send the batch request
        response = requests.post(
            f"{llm_proxy_url}/{app_method}",
            headers=headers,
            json=payload,
            verify=False,
            timeout=600, # Increased timeout for potential long batch processing
        )

        if response.status_code != 200:
            logger.error(
                f"❌ Failed batch request. Status={response.status_code}, body={response.text}"
            )
            return 0
            
        logger.info(f"[GCP-RESPONSE-RAW] Received successful response from GCP. Body:\n{response.text}")
        
        # 3. Process the batch response
        try:
            full_response = response.json()
        except ValueError:
            logger.error(f"❌ Invalid JSON in batch response. Raw body:\n{response.text}")
            return 0

        # Normalize structure — handle both list or dict response formats
        if isinstance(full_response, list):
            results = full_response
            logger.info(f"[GCP-RESPONSE] ✅ Received list response with {len(results)} results.")
        elif isinstance(full_response, dict):
            results = full_response.get("results", [])
            logger.info(f"[GCP-RESPONSE] ✅ Received dict response with {len(results)} results (keys: {list(full_response.keys())}).")
        else:
            logger.error(f"❌ Unexpected response type: {type(full_response)}. Expected list or dict. Full body:\n{response.text}")
            return 0

        # Validate the results list
        if not isinstance(results, list):
            logger.error(f"❌ 'results' key is not a list — got {type(results)}. Full body:\n{json.dumps(full_response, indent=2)[:1000]}")
            return 0

            
        # Check count consistency
        if len(results) != len(ticket_jsons_for_payload):
            logger.warning(
                f"⚠️ Mismatch: Sent {len(ticket_jsons_for_payload)} tickets, received {len(results)} responses. "
                "Responses cannot be reliably matched to tickets. Skipping DB updates."
            )
            return 0
        
        # 4. Iterate through responses and update DB
        for i, result in enumerate(results):
            ticket_data = ticket_map.get(i)
            if not ticket_data:
                logger.error(f"Internal error: Could not find ticket data for response index {i}. Skipping.")
                continue

            ticket_id = ticket_data["id"]
            expected_ticket_number = ticket_data["number"]
            response_ticket_number = result.get("ticket_number") 

            
            if str(response_ticket_number) != str(expected_ticket_number):
                logger.warning(f"⚠️ Ticket number mismatch! Expected {expected_ticket_number}, got {response_ticket_number} in response at index {i}. Skipping update for safety.")
                continue

            try:
                # Insert the full result object for traceability
                insert_response(conn, response_ticket_number, result) 
                mark_ticket_processed(conn, ticket_id)
                processed_count += 1
                logger.info(f"✅ Successfully processed and updated DB for ticket {response_ticket_number}")

            except Exception as e:
                logger.error(f"Exception while processing successful response for ticket {response_ticket_number}: {e}\n{traceback.format_exc()}")
        
        
    except Exception as e:
        logger.error(f"Exception during batch request: {e}\n{traceback.format_exc()}")
        
    return processed_count


# ─────────────────────────────────────────────
# Lambda Handler
# ─────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Main handler function for the AWS Lambda.
    """
    conn = None
    try:
        # --- Load environment variables ---
        env_vars = {
            name: os.environ[name] 
            for name in [
                "RDS_SECRET_NAME", "GCP_SECRET_NAME", "RDS_HOST", "RDS_PORT", 
                "RDS_DB", "PROJECT_ID", "SERVICE_NAME", "AIG_PROJECT", 
                "CLIENT_ID", "APP_METHOD", "CR_AUDIENCE"
            ]
        }
        RDS_PORT = int(env_vars["RDS_PORT"])

        # --- Fetch secrets ---
        rds_secret = get_secret(env_vars["RDS_SECRET_NAME"])
        gcp_key = get_secret(env_vars["GCP_SECRET_NAME"])

        # --- Write GCP key to /tmp (fix escaped newlines) ---
        gcp_key_path = "/tmp/gcp_key.json"
        if "private_key" in gcp_key:
            gcp_key["private_key"] = gcp_key["private_key"].replace("\\n", "\n")
        with open(gcp_key_path, "w") as f:
            json.dump(gcp_key, f)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = gcp_key_path
        logger.info(f"GCP key written to {gcp_key_path}")

        # --- DB connection ---
        conn = get_db_connection(rds_secret, env_vars["RDS_HOST"], RDS_PORT, env_vars["RDS_DB"])

        # --- Fetch all tickets ---
        tickets = fetch_tickets(conn)
        if not tickets:
            logger.info("No tickets found to process.")
            return {"status": "done", "processed": 0, "message": "No tickets found."}

        # --- GCP IAP tokens and headers ---
        cloudrun_token = make_authorized_get_request(env_vars["CR_AUDIENCE"])
        iap_token = get_iap_token(env_vars["CLIENT_ID"])

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {iap_token}",
            "X-Serverless-Authorization": f"Bearer {cloudrun_token}",
        }

        llm_proxy_url = (
            f"https://{env_vars['AIG_PROJECT']}-elb.aib.vodafone.com/"
            f"{env_vars['PROJECT_ID']}/{env_vars['SERVICE_NAME']}"
        )
        
        # ─── Process the batch ──────────────
        processed_count = process_ticket_batch(
            conn, 
            tickets, 
            llm_proxy_url, 
            env_vars["APP_METHOD"], 
            headers
        )

        return {"status": "done", "processed": processed_count}

    except Exception as e:
        logger.fatal(f"Fatal error in Lambda: {e}\n{traceback.format_exc()}")
        return {"status": "error", "message": str(e)}
    
    finally:
        # --- Clean up DB connection ---
        if conn:
            conn.close()
            logger.info("Database connection closed.")