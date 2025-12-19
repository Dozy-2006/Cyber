import gspread
from oauth2client.service_account import ServiceAccountCredentials
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
from datetime import datetime
import re
import pandas as pd
from gspread_dataframe import set_with_dataframe
import gspread.utils
import pyotp
import secrets
import qrcode
import base64
import io

# --- 1. SETUP & INITIALIZATION ---
app = Flask(__name__)
CORS(app)

# --- 2. GOOGLE SHEETS CONNECTION ---
scope = ["https://spreadsheets.google.com/feeds", 'https://www.googleapis.com/auth/spreadsheets',
         "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive"]
try:
    creds = ServiceAccountCredentials.from_json_keyfile_name(r"C:\Users\PRAKASH\Documents\Cyber\venv\credentials.json", scope)
    client = gspread.authorize(creds)
    config_sheet = client.open("App_Configuration")
    users_worksheet = config_sheet.worksheet("Users")
    master_worksheet = config_sheet.worksheet("Master_File_Index")
    schema_worksheet = config_sheet.worksheet("Schema_Definitions")
    permissions_worksheet = config_sheet.worksheet("Sheet_Permissions")
    activity_log_worksheet = config_sheet.worksheet("Activity_Log")
    print("Successfully connected to Google Sheets.")
except Exception as e:
    print(f"FATAL ERROR: Could not connect to Google Sheets. Check credentials path and permissions. Error: {e}")
    exit()

# --- 3. HELPER FUNCTIONS ---
# ... (No changes in helper functions) ...
def is_valid_date(date_string):
    if not date_string: return True
    try:
        datetime.strptime(str(date_string), '%Y-%m-%d')
        return True
    except (ValueError, TypeError):
        return False

def apply_autocorrect(data_dict, schema):
    corrected_data = data_dict.copy()
    schema_map = {field.get('name'): field for field in schema}
    for field_name, value in corrected_data.items():
        rule = schema_map.get(field_name)
        if not rule or value is None: continue
        value_str = str(value).strip()
        if rule.get('type') in ['pan', 'vehicle_number', 'time_12hr']:
            value_str = value_str.upper()
        corrected_data[field_name] = value_str
        if rule.get('type') == 'date' and value_str:
            try:
                corrected_date = pd.to_datetime(value_str, errors='coerce')
                if pd.notna(corrected_date):
                    corrected_data[field_name] = corrected_date.strftime('%Y-%m-%d')
            except Exception: pass
    return corrected_data

def validate_case_data(case_data, schema):
    for field in schema:
        field_name, value = field.get('name'), case_data.get(field.get('name'))
        value_str = str(value or '').strip()
        is_required = field.get('required')
        if (is_required is True or str(is_required).lower() == 'true') and not value_str:
            return f"'{field_name}' is a required field."
        if not value_str: continue
        field_type = field.get('type')
        length = field.get('length')
        fmt = field.get('format')
        is_fixed_raw = field.get('isFixed', False)
        is_fixed = is_fixed_raw is True or str(is_fixed_raw).lower() == 'true'

        if field_type == 'options':
            allowed_options = field.get('options', [])
            if value_str not in allowed_options:
                return f"Invalid value for '{field_name}'. It must be one of: {', '.join(allowed_options)}."
        elif field_type == 'date':
            if not is_valid_date(value_str): return f"Invalid date format for '{field_name}'. Use YYYY-MM-DD."
        elif field_type == 'year':
            if not (value_str.isdigit() and len(value_str) == 4): return f"'{field_name}' must be a 4-digit Year."
        elif field_type == 'pincode':
            if not (value_str.isdigit() and len(value_str) == 6): return f"'{field_name}' must be a 6-digit Pincode."
        elif field_type == 'phone_number':
            if not (value_str.isdigit() and len(value_str) == 10): return f"'{field_name}' must be a 10-digit Phone Number."
        elif field_type == 'aadhar':
            if not (value_str.isdigit() and len(value_str) == 12): return f"'{field_name}' must be a 12-digit Aadhar Number."
        elif field_type == 'police_number':
            if not (value_str.isdigit() and 3 <= len(value_str) <= 4): return f"'{field_name}' must be a 3 or 4-digit Police Number."
        elif field_type == 'pan':
            if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', value_str.upper()): return f"'{field_name}' is not a valid PAN format."
        elif field_type == 'vehicle_number':
            if not re.match(r'^[A-Z]{2}[0-9]{1,2}[A-Z]{1,2}[0-9]{4}$', value_str.upper()): return f"'{field_name}' is not a valid Vehicle Number format (e.g., TN01AB1234)."
        elif field_type == 'time_24hr':
            if not re.match(r'^([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?$', value_str): return f"'{field_name}' is not a valid 24-hour time format (HH:MM)."
        elif field_type == 'time_12hr':
            if not re.match(r'^(0?[1-9]|1[0-2]):([0-5]\d)(?::([0-5]\d))?\s?[AP]M$', value_str.upper()): return f"'{field_name}' is not a valid 12-hour time format (e.g., 01:30 PM)."
        elif fmt:
            regex_pattern = '^' + ''.join([r'\d' if c == '_' and field_type == 'number' else r'.' if c == '_' else re.escape(c) for c in fmt]) + '$'
            if not re.match(regex_pattern, value_str): return f"'{field_name}' value '{value_str}' does not match format '{fmt}'."
        elif field_type == 'number' and not value_str.isdigit(): return f"'{field_name}' must contain only digits."
        elif (field_type == 'number' or field_type == 'text') and length:
            try:
                length = int(length)
                if field_type == 'number' and is_fixed and len(value_str) != length: return f"'{field_name}' must be exactly {length} digits."
                if len(value_str) > length: return f"'{field_name}' cannot be more than {length} characters/digits."
            except (ValueError, TypeError): pass
    return None

# --- 4. AUTHENTICATION & USER MANAGEMENT ---
@app.route('/login', methods=['POST'])
def authenticateUser():
    login_data = request.get_json()
    role, username, otp_code = login_data.get('role', '').strip().lower(), login_data.get('username', '').strip(), login_data.get('password', '')
    if not all([role, username, otp_code]): return jsonify({"success": False, "message": "All fields are required."}), 400
    for user_record in users_worksheet.get_all_records():
        user = {k.strip().lower(): v for k, v in user_record.items()}
        if user.get('username', '').lower() == username.lower() and user.get('role', '').lower() == role:
            totp_secret = user.get('totpsecret')
            if not totp_secret: return jsonify({"success": False, "message": "Authenticator not configured for this user."}), 400
            if pyotp.TOTP(totp_secret).verify(otp_code):
                print(f"Successful TOTP login for user: {username}")
                user_details = { "username": user_record.get('Username'), "role": user_record.get('Role'), "accessScope": user_record.get('AccessScope'), "gender": user_record.get('Gender') }
                return jsonify({"success": True, "user": user_details})
            else: break
    print(f"Failed login attempt for user: {username}")
    return jsonify({"success": False, "message": "Invalid credentials."}), 401

@app.route('/admin/get-all-users', methods=['GET'])
def get_all_users():
    try:
        users = users_worksheet.get_all_records()
        users_to_return = [{k: v for k, v in u.items() if k.strip().lower() not in ['hashedpassword', 'totpsecret']} for u in users]
        return jsonify({"success": True, "users": users_to_return})
    except Exception as e: return jsonify({"success": False, "message": f"Could not fetch users: {e}"}), 500

@app.route('/admin/add-user', methods=['POST'])
def add_user():
    req_data = request.get_json()
    username, role, access_scope, gender, station = req_data.get('username','').strip(), req_data.get('role','').strip(), req_data.get('accessScope', 'all').strip(), req_data.get('gender','').strip(), req_data.get('station','').strip()
    if not all([username, role, gender, station]): return jsonify({"success": False, "message": "All fields are required."}), 400
    try:
        if username.lower() in [str(u.get('Username', '')).strip().lower() for u in users_worksheet.get_all_records()]:
            return jsonify({"success": False, "message": f"User '{username}' already exists."}), 409
        
        totp_secret = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(12))
        
        issuer_name = "CaseManagementApp"
        otp_uri = f"otpauth://totp/{issuer_name}:{username}?secret={totp_secret}&issuer={issuer_name}"
        qr_img = qrcode.make(otp_uri)
        buffered = io.BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_code_base64_string = base64.b64encode(buffered.getvalue()).decode('utf-8')

        users_worksheet.append_row([username, "", role, access_scope, gender, station, totp_secret])
        
        return jsonify({
            "success": True, 
            "message": f"User '{username}' created.", 
            "username": username,
            "totp_secret_key": totp_secret,
            "qr_code_image": qr_code_base64_string
        })
    except Exception as e: 
        print(f"Error during user creation: {e}")
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

@app.route('/admin/change-password', methods=['POST'])
def admin_reset_totp_key():
    username = request.get_json().get('username','').strip()
    if not username: return jsonify({"success": False, "message": "Username is required."}), 400
    try:
        cell = users_worksheet.find(re.compile(f"^{re.escape(username)}$", re.IGNORECASE), in_column=1)
        if not cell: return jsonify({"success": False, "message": f"User '{username}' not found."}), 404
        
        key_col_index = [h.strip().lower() for h in users_worksheet.row_values(1)].index('totpsecret') + 1
        new_totp_secret = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(12))
        
        issuer_name = "CaseManagementApp"
        otp_uri = f"otpauth://totp/{issuer_name}:{username}?secret={new_totp_secret}&issuer={issuer_name}"
        qr_img = qrcode.make(otp_uri)
        buffered = io.BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_code_base64_string = base64.b64encode(buffered.getvalue()).decode('utf-8')
        
        users_worksheet.update_cell(cell.row, key_col_index, new_totp_secret)
        
        return jsonify({
            "success": True, 
            "message": f"Key for '{username}' has been reset.",
            "username": username,
            "totp_secret_key": new_totp_secret,
            "qr_code_image": qr_code_base64_string
        })
    except Exception as e: 
        print(f"Error during key reset: {e}")
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

# --- 5. DATA FETCHING ---
@app.route('/get-data', methods=['POST'])
def getData():
    req_data = request.get_json()
    user_data = req_data.get('user')
    spreadsheet_id_override = req_data.get('spreadsheet_id')
    if not user_data: return jsonify({"success": False, "message": "User data not provided"}), 400
    role = user_data.get('role', '').strip().lower()

    if (role == 'admin') or (role == 'sdo' and not spreadsheet_id_override):
        return jsonify({"success": True, "locations": master_worksheet.get_all_records()})

    spreadsheet_id = spreadsheet_id_override
    if not spreadsheet_id and role == 'normal':
        access_scope = user_data.get('accessScope', '').strip()
        for loc in master_worksheet.get_all_records():
            if loc.get('LocationName', '').strip().lower() == access_scope.lower():
                spreadsheet_id = loc.get('Spreadsheet_ID')
                break

    if not spreadsheet_id: return jsonify({"success": False, "message": "Location not found or not assigned"}), 404

    try:
        sheet = client.open_by_key(spreadsheet_id)
        all_tabs_in_sheet = {ws.title for ws in sheet.worksheets()}
        all_permissions = permissions_worksheet.get_all_records()

        restricted_sheets = {p['SheetName'] for p in all_permissions if p.get('SpreadsheetID') == spreadsheet_id}
        user_assigned_tabs = {p['SheetName'] for p in all_permissions if p.get('AssignedUser', '').lower() == user_data.get('username', '').lower() and p.get('SpreadsheetID') == spreadsheet_id}

        schema_rules = {s.get('CaseType'): s.get('IsFemaleOnly', 'FALSE') for s in schema_worksheet.get_all_records()}
        user_gender = str(user_data.get('gender', '')).strip().lower()
        gender_allowed_tabs = {tab for tab in all_tabs_in_sheet if not (str(schema_rules.get(tab, 'FALSE')).strip().upper() == 'TRUE' and user_gender != 'female')}

        categorized = { "restricted": [], "role_based": [] }
        for tab in gender_allowed_tabs:
            if tab in restricted_sheets:
                if tab in user_assigned_tabs:
                    categorized["restricted"].append(tab)
            else:
                categorized["role_based"].append(tab)

        for key in categorized: categorized[key].sort()

        response_data = {"success": True, "spreadsheet_id": spreadsheet_id}
        if role == 'normal' or role == 'sdo':
            response_data["categorized_sheets"] = categorized
        else:
            response_data["allowed_tabs"] = sorted(list(gender_allowed_tabs))
        return jsonify(response_data)
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not access spreadsheet configuration: {e}"}), 500

@app.route('/get-sheet-data', methods=['POST'])
def get_sheet_data():
    req_data = request.get_json()
    spreadsheet_id, tab_name, search_query = req_data.get('spreadsheet_id'), req_data.get('tab_name'), req_data.get('search_query', '').lower().strip()
    if not all([spreadsheet_id, tab_name]): return jsonify({"success": False, "message": "Missing required data"}), 400
    try:
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        all_data = worksheet.get_all_records()
        headers = worksheet.row_values(1) if worksheet.row_count > 0 else []

        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('SchemaPath', '').strip() == f"{spreadsheet_id}/{tab_name}":
                schema = json.loads(s.get('SchemaJSON', '[]'))
                break

        if search_query:
            all_data = [row for row in all_data if any(search_query in str(v).lower() for v in row.values())]

        return jsonify({"success": True, "data": all_data, "headers": headers, "schema": schema})
    except gspread.exceptions.WorksheetNotFound: return jsonify({"success": False, "message": f"Tab '{tab_name}' not found"}), 404
    except Exception as e: return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500


# --- 6. DATA MODIFICATION (SINGLE & BULK) ---
# *** DEFINITIVE DELETION FIX: Replace complex batching with a simple, robust loop ***
@app.route('/bulk-update-cases', methods=['POST'])
def bulk_update_cases():
    req_data = request.get_json()
    spreadsheet_id, tab_name = req_data.get('spreadsheet_id'), req_data.get('tab_name')
    updates, additions, deletions = req_data.get('updates', []), req_data.get('additions', []), req_data.get('deletions', [])

    if not all([spreadsheet_id, tab_name]):
        return jsonify({"success": False, "message": "Missing spreadsheet or tab name."}), 400
    if not any([updates, additions, deletions]):
        return jsonify({"success": True, "message": "No changes to save."})

    try:
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        headers = worksheet.row_values(1)
        case_id_header = next((h for h in headers if h.lower() == 'caseid'), None)
        if not case_id_header:
            return jsonify({"success": False, "message": "Critical Error: 'CaseID' column not found in the sheet."}), 500

        # --- DELETION LOGIC (ROBUST VERSION) ---
        if deletions:
            # Find all rows to be deleted first. This is safer than relying on client-side indices.
            all_records = worksheet.get_all_records()
            rows_to_delete_indices = []
            for i, record in enumerate(all_records):
                # The row number in the sheet is the index (i) + 2 (1 for 1-based index, 1 for header)
                if str(record.get(case_id_header)) in deletions:
                    rows_to_delete_indices.append(i + 2)
            
            # Delete rows one by one from the bottom up to avoid index shifting issues.
            # This is the most reliable method.
            if rows_to_delete_indices:
                for row_index in sorted(rows_to_delete_indices, reverse=True):
                    worksheet.delete_rows(row_index)
        
        # --- ADDITION LOGIC ---
        if additions:
            rows_to_append = [[item.get('case_data', {}).get(h, "") for h in headers] for item in additions]
            if rows_to_append:
                worksheet.append_rows(rows_to_append, value_input_option='USER_ENTERED')

        # --- UPDATE LOGIC ---
        if updates:
            # Get a fresh view of the data AFTER deletions and additions
            all_data_after_changes = worksheet.get_all_records()
            data_map_after_changes = {str(row.get(case_id_header)): (i + 2, row) for i, row in enumerate(all_data_after_changes)}
            
            batch_update_payload = []
            for update_item in updates:
                case_id = str(update_item.get('case_id'))
                if case_id in data_map_after_changes:
                    row_num, existing_row_data = data_map_after_changes[case_id]
                    updated_row_values = [update_item.get('new_data', {}).get(header, existing_row_data.get(header, "")) for header in headers]
                    batch_update_payload.append({
                        'range': f'A{row_num}:{chr(ord("A") + len(headers) - 1)}{row_num}',
                        'values': [updated_row_values]
                    })
            if batch_update_payload:
                worksheet.batch_update(batch_update_payload, value_input_option='USER_ENTERED')
        
        return jsonify({"success": True, "message": "All changes saved successfully."})

    except Exception as e:
        error_message = f"An error occurred during bulk update: {str(e)}"
        print(error_message) 
        return jsonify({"success": False, "message": error_message}), 500

@app.route('/add-case', methods=['POST'])
def add_case():
    req_data = request.get_json()
    spreadsheet_id, tab_name, case_data, should_validate = req_data.get('spreadsheet_id'), req_data.get('tab_name'), req_data.get('case_data'), req_data.get('should_validate', True)
    if not all([spreadsheet_id, tab_name, case_data]): return jsonify({"success": False, "message": "Missing required data"}), 400
    try:
        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('SchemaPath') == f"{spreadsheet_id}/{tab_name}":
                schema = json.loads(s.get('SchemaJSON', '[]'))
                break
        corrected_data = apply_autocorrect(case_data, schema)
        if should_validate:
            error = validate_case_data(corrected_data, schema)
            if error: return jsonify({"success": False, "message": error}), 400
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        headers = worksheet.row_values(1)
        case_id_header = next((h for h in headers if h.lower() == 'caseid'), headers[0])
        new_case_id = corrected_data.get(case_id_header)
        if not new_case_id: return jsonify({"success": False, "message": f"'{case_id_header}' cannot be empty."}), 400
        if new_case_id in set(worksheet.col_values(headers.index(case_id_header) + 1)):
            return jsonify({"success": False, "message": f"'{case_id_header}' '{new_case_id}' already exists."}), 409
        worksheet.append_row([corrected_data.get(h, "") for h in headers])
        return jsonify({"success": True, "message": "Case added successfully."})
    except Exception as e: return jsonify({"success": False, "message": f"Failed to add case: {e}"}), 500
@app.route('/edit-case', methods=['POST'])
def edit_case():
    req_data = request.get_json()
    spreadsheet_id, tab_name, case_id, new_data, should_validate = req_data.get('spreadsheet_id'), req_data.get('tab_name'), req_data.get('case_id'), req_data.get('new_data'), req_data.get('should_validate', True)
    if not all([spreadsheet_id, tab_name, case_id, new_data]): return jsonify({"success": False, "message": "Missing required data"}), 400
    schema = []
    for s in schema_worksheet.get_all_records():
        if s.get('SchemaPath') == f"{spreadsheet_id}/{tab_name}":
            schema = json.loads(s.get('SchemaJSON', '[]'))
            break
    corrected_data = apply_autocorrect(new_data, schema)
    if should_validate:
        error = validate_case_data(corrected_data, schema)
        if error: return jsonify({"success": False, "message": error}), 400
    try:
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        cell = worksheet.find(str(case_id))
        if not cell: return jsonify({"success": False, "message": "CaseID not found"}), 404
        headers = worksheet.row_values(1)
        worksheet.update(f'A{cell.row}:{chr(ord("A")+len(headers)-1)}{cell.row}', [[corrected_data.get(h, "") for h in headers]])
        return jsonify({"success": True, "message": "Case updated successfully."})
    except Exception as e: return jsonify({"success": False, "message": f"Failed to update case: {e}"}), 500
@app.route('/delete-case', methods=['POST'])
def delete_case():
    req_data = request.get_json()
    spreadsheet_id, tab_name, case_id = req_data.get('spreadsheet_id'), req_data.get('tab_name'), req_data.get('case_id')
    if not all([spreadsheet_id, tab_name, case_id]): return jsonify({"success": False, "message": "Missing required data"}), 400
    try:
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        cell = worksheet.find(str(case_id))
        if not cell: return jsonify({"success": False, "message": "CaseID not found"}), 404
        worksheet.delete_rows(cell.row)
        return jsonify({"success": True, "message": "Case permanently deleted."})
    except Exception as e: return jsonify({"success": False, "message": f"Failed to delete case: {e}"}), 500
@app.route('/bulk-add-cases', methods=['POST'])
def bulk_add_cases():
    req_data = request.get_json()
    spreadsheet_id, tab_name, cases_data, should_validate = req_data.get('spreadsheet_id'), req_data.get('tab_name'), req_data.get('cases_data'), req_data.get('should_validate', True)
    if not all([spreadsheet_id, tab_name, cases_data]): return jsonify({"success": False, "message": "Missing required data."}), 400
    if not isinstance(cases_data, list) or not cases_data: return jsonify({"success": False, "message": "No cases provided."}), 400
    try:
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        headers = worksheet.row_values(1)
        case_id_header = next((h for h in headers if h.lower() == 'caseid'), headers[0])
        existing_ids = set(worksheet.col_values(headers.index(case_id_header) + 1))
        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('SchemaPath') == f"{spreadsheet_id}/{tab_name}":
                schema = json.loads(s.get('SchemaJSON', '[]'))
                break
        final_rows = []
        for i, case_data in enumerate(cases_data):
            corrected = apply_autocorrect(case_data, schema)
            case_id = corrected.get(case_id_header)
            if not case_id: return jsonify({"success": False, "message": f"Row {i+2}: '{case_id_header}' is empty."}), 400
            if case_id in existing_ids: return jsonify({"success": False, "message": f"Row {i+2}: Duplicate ID '{case_id}'."}), 409
            if should_validate:
                error = validate_case_data(corrected, schema)
                if error: return jsonify({"success": False, "message": f"Row {i+2}: {error}"}), 400
            final_rows.append([corrected.get(h, "") for h in headers])
            existing_ids.add(case_id)
        if final_rows: worksheet.append_rows(final_rows)
        return jsonify({"success": True, "message": f"{len(final_rows)} cases added successfully."})
    except Exception as e: return jsonify({"success": False, "message": f"Failed to bulk add cases: {e}"}), 500

# --- 7. ADMIN & VALIDATION ENDPOINTS ---
@app.route('/validate-and-format-sheet', methods=['POST'])
def validate_and_format_sheet():
    req_data = request.get_json()
    spreadsheet_id, tab_name = req_data.get('spreadsheet_id'), req_data.get('tab_name')
    if not all([spreadsheet_id, tab_name]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        worksheet = client.open_by_key(spreadsheet_id).worksheet(tab_name)
        all_data = worksheet.get_all_values()
        if len(all_data) < 2: return jsonify({"success": True, "message": "Sheet has no data to validate.", "error_cells": [], "data": []})

        headers = all_data[0]
        df = pd.DataFrame(all_data[1:], columns=headers)

        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('SchemaPath') == f"{spreadsheet_id}/{tab_name}":
                schema = json.loads(s.get('SchemaJSON', '[]'))
                break
        if not schema: return jsonify({"success": False, "message": f"No schema found for '{tab_name}'."}), 404

        error_cells_a1 = []
        corrected_df = df.copy()

        for index, row in corrected_df.iterrows():
            corrected_row_dict = apply_autocorrect(row.to_dict(), schema)
            for col_name, value in corrected_row_dict.items():
                corrected_df.at[index, col_name] = value

        for r_idx, row in corrected_df.iterrows():
            for c_idx, col_name in enumerate(headers):
                rule = next((r for r in schema if r['name'] == col_name), None)
                if rule:
                    validation_error = validate_case_data({col_name: row[col_name]}, [rule])
                    if validation_error:
                        error_cells_a1.append(gspread.utils.rowcol_to_a1(r_idx + 2, c_idx + 1))

        corrected_df = corrected_df.astype(str).replace('nan', '')
        set_with_dataframe(worksheet, corrected_df, include_index=False, resize=True)
        
        if worksheet.row_count > 1:
            worksheet.format(f"A2:{chr(ord('A') + len(headers) - 1)}{worksheet.row_count}", {"backgroundColor": {"red": 1, "green": 1, "blue": 1}})

        if error_cells_a1:
            worksheet.format(error_cells_a1, {"backgroundColor": {"red": 0.98, "green": 0.8, "blue": 0.8}})

        message = f"Validation complete. Found {len(error_cells_a1)} errors." if error_cells_a1 else "Validation complete. No errors found."
        
        corrected_data_for_frontend = corrected_df.to_dict('records')

        return jsonify({
            "success": True, 
            "message": message, 
            "error_cells": error_cells_a1, 
            "data": corrected_data_for_frontend
        })
    except Exception as e:
        error_message = f"An error occurred during validation: {str(e)}"
        print(error_message)
        return jsonify({"success": False, "message": error_message}), 500

# ... (The rest of the backend file remains the same) ...
@app.route('/admin/get-sheets-for-location', methods=['POST'])
def get_sheets_for_location():
    spreadsheet_id = request.get_json().get('spreadsheet_id')
    if not spreadsheet_id: return jsonify({"success": False, "message": "Spreadsheet ID is required."}), 400
    try:
        sheet_names = [ws.title for ws in client.open_by_key(spreadsheet_id).worksheets()]
        return jsonify({"success": True, "sheet_names": sheet_names})
    except Exception as e: return jsonify({"success": False, "message": f"Could not get sheets: {e}"}), 500
@app.route('/admin/delete-sheet', methods=['POST'])
def delete_sheet_endpoint():
    req_data = request.get_json()
    spreadsheet_id, sheet_name = req_data.get('spreadsheet_id'), req_data.get('sheet_name')
    if not all([spreadsheet_id, sheet_name]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        spreadsheet = client.open_by_key(spreadsheet_id)
        spreadsheet.del_worksheet(spreadsheet.worksheet(sheet_name))

        try:
            cell = schema_worksheet.find(f"{spreadsheet_id}/{sheet_name}", in_column=4)
            if cell: schema_worksheet.delete_rows(cell.row)
        except gspread.exceptions.CellNotFound: pass

        all_perms = permissions_worksheet.get_all_values()
        rows_to_delete = [i + 1 for i, row in enumerate(all_perms) if len(row) > 1 and row[0] == spreadsheet_id and row[1] == sheet_name]
        for index in sorted(rows_to_delete, reverse=True):
            permissions_worksheet.delete_rows(index)

        return jsonify({"success": True, "message": f"Sheet '{sheet_name}' and its permissions have been deleted."})
    except Exception as e: return jsonify({"success": False, "message": f"An error occurred: {e}"}), 500

@app.route('/add-sheet', methods=['POST'])
def add_sheet_endpoint():
    req_data = request.get_json()
    spreadsheet_id, sheet_name, schema = req_data.get('spreadsheet_id'), req_data.get('sheet_name', '').strip(), req_data.get('schema')
    is_restricted = req_data.get('is_restricted', False)

    if not all([spreadsheet_id, sheet_name, schema]):
        return jsonify({"success": False, "message": "Missing required data."}), 400

    headers = [field['name'].strip() for field in schema if field.get('name')]
    if len(headers) != len(set(headers)):
        return jsonify({"success": False, "message": "Column names must be unique."}), 400

    try:
        spreadsheet = client.open_by_key(spreadsheet_id)
        if sheet_name.lower() in [s.title.lower() for s in spreadsheet.worksheets()]:
            return jsonify({"success": False, "message": f"Sheet '{sheet_name}' already exists."}), 409

        worksheet = spreadsheet.add_worksheet(title=sheet_name, rows="100", cols=len(headers))
        worksheet.append_row(headers)

        schema_worksheet.append_row([sheet_name, json.dumps(schema), "FALSE", f"{spreadsheet_id}/{sheet_name}"])

        if is_restricted:
            permissions_worksheet.append_row([spreadsheet_id, sheet_name, ""])

        return jsonify({"success": True, "message": f"Sheet '{sheet_name}' created."})
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {e}"}), 500
@app.route('/add-location', methods=['POST'])
def add_location():
    req_data = request.get_json()
    location_name, spreadsheet_id = req_data.get('location_name','').strip(), req_data.get('spreadsheet_id','').strip()
    if not all([location_name, spreadsheet_id]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        if location_name.lower() in [l.get('LocationName', '').lower() for l in master_worksheet.get_all_records()]:
            return jsonify({"success": False, "message": "This location name already exists."}), 409
        master_worksheet.append_row([location_name, spreadsheet_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        return jsonify({"success": True, "message": "New location registered."})
    except Exception as e: return jsonify({"success": False, "message": f"An error occurred: {e}"}), 500
@app.route('/admin/delete-location', methods=['POST'])
def delete_location():
    location_name = request.get_json().get('location_name', '').strip()
    if not location_name: return jsonify({"success": False, "message": "Location name is required."}), 400
    try:
        cell = master_worksheet.find(re.compile(f"^{re.escape(location_name)}$", re.IGNORECASE))
        if not cell: return jsonify({"success": False, "message": f"Location '{location_name}' not found."}), 404
        master_worksheet.delete_rows(cell.row)
        return jsonify({"success": True, "message": f"Location '{location_name}' deleted."})
    except Exception as e: return jsonify({"success": False, "message": f"An error occurred: {e}"}), 500
@app.route('/admin/get-sheet-schema', methods=['POST'])
def get_sheet_schema():
    req_data = request.get_json()
    spreadsheet_id, sheet_name = req_data.get('spreadsheet_id', ''), req_data.get('sheet_name', '')
    if not all([spreadsheet_id, sheet_name]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        for s in schema_worksheet.get_all_records():
            if s.get('SchemaPath') == f"{spreadsheet_id}/{sheet_name}":
                return jsonify({"success": True, "schema": json.loads(s.get('SchemaJSON', '[]'))})
        return jsonify({"success": False, "message": "Schema not found."}), 404
    except Exception as e: return jsonify({"success": False, "message": f"Error fetching schema: {e}"}), 500
@app.route('/admin/edit-sheet', methods=['POST'])
def edit_sheet():
    req_data = request.get_json()
    spreadsheet_id, sheet_name, new_fields = req_data.get('spreadsheet_id'), req_data.get('sheet_name'), req_data.get('new_fields', [])
    if not all([spreadsheet_id, sheet_name, new_fields]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        cell = schema_worksheet.find(f"{spreadsheet_id}/{sheet_name}", in_column=4)
        if not cell: return jsonify({"success": False, "message": "Schema not found."}), 404
        existing_schema = json.loads(schema_worksheet.cell(cell.row, 2).value)
        existing_names = {f['name'].lower() for f in existing_schema}
        for field in new_fields:
            if field['name'].lower() in existing_names: return jsonify({"success": False, "message": f"Column '{field['name']}' already exists."}), 409
        schema_worksheet.update_cell(cell.row, 2, json.dumps(existing_schema + new_fields))
        worksheet = client.open_by_key(spreadsheet_id).worksheet(sheet_name)
        worksheet.add_cols(len(new_fields))
        last_col = len(worksheet.row_values(1))
        worksheet.update(gspread.utils.rowcol_to_a1(1, last_col + 1), [[f['name'] for f in new_fields]])
        return jsonify({"success": True, "message": f"Added {len(new_fields)} new column(s) to '{sheet_name}'."})
    except Exception as e: return jsonify({"success": False, "message": f"An error occurred: {e}"}), 500

# --- 8. REPORTING, PERMISSION & COMMON SHEETS ENDPOINTS ---
@app.route('/admin/get-activity-log', methods=['POST'])
def get_activity_log():
    req_data = request.get_json()
    spreadsheet_id, sheet_name, location_name = req_data.get('spreadsheet_id'), req_data.get('sheet_name'), req_data.get('location_name')
    if not all([spreadsheet_id, sheet_name, location_name]):
        return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        all_users = users_worksheet.get_all_records()
        all_permissions = permissions_worksheet.get_all_records()
        is_restricted = any(p for p in all_permissions if p.get('SpreadsheetID') == spreadsheet_id and p.get('SheetName') == sheet_name)
        relevant_users = []
        if is_restricted:
            assigned_usernames = {p['AssignedUser'].lower() for p in all_permissions if p.get('SpreadsheetID') == spreadsheet_id and p.get('SheetName') == sheet_name and p.get('AssignedUser')}
            relevant_users = [user for user in all_users if user.get('Username').lower() in assigned_usernames]
        else:
            relevant_users = [user for user in all_users if user.get('Role') == 'sdo' or (user.get('Role') == 'normal' and user.get('AccessScope') == location_name)]

        all_logs = activity_log_worksheet.get_all_records()
        latest_logs = {log['Username']: log for log in all_logs if log.get('SpreadsheetID') == spreadsheet_id and log.get('SheetName') == sheet_name}

        report = []
        for user in relevant_users:
            username, user_log = user.get('Username'), latest_logs.get(user.get('Username'))
            if user_log:
                report.append({"Username": username, "Station": user.get('Station', 'N/A'), "Status": user_log.get('Action'), "Timestamp": user_log.get('Timestamp')})
            else:
                report.append({"Username": username, "Station": user.get('Station', 'N/A'), "Status": "Not Viewed", "Timestamp": None})

        return jsonify({"success": True, "report": report, "is_restricted": is_restricted})
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not fetch activity report: {e}"}), 500

@app.route('/log-user-action', methods=['POST'])
def log_user_action():
    req_data = request.get_json()
    username, spreadsheet_id, sheet_name, action = req_data.get('username'), req_data.get('spreadsheet_id'), req_data.get('tab_name'), req_data.get('action')
    if not all([username, spreadsheet_id, sheet_name, action]):
        return jsonify({"success": False, "message": "Missing data for logging action."}), 400
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        activity_log_worksheet.append_row([username, spreadsheet_id, sheet_name, action, timestamp])
        return jsonify({"success": True, "message": "Your report has been submitted to the admin."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not log your action: {e}"}), 500
@app.route('/admin/get-sheet-permissions', methods=['POST'])
def get_sheet_permissions():
    req_data = request.get_json()
    spreadsheet_id, sheet_name = req_data.get('spreadsheet_id'), req_data.get('sheet_name')
    if not all([spreadsheet_id, sheet_name]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        all_permissions = permissions_worksheet.get_all_records()
        assigned_users = [p['AssignedUser'] for p in all_permissions if p.get('SpreadsheetID') == spreadsheet_id and p.get('SheetName') == sheet_name and p.get('AssignedUser')]
        return jsonify({"success": True, "assigned_users": assigned_users})
    except Exception as e: return jsonify({"success": False, "message": f"Could not fetch permissions: {e}"}), 500
@app.route('/admin/set-sheet-permissions', methods=['POST'])
def set_sheet_permissions():
    req_data = request.get_json()
    spreadsheet_id, sheet_name, assigned_users = req_data.get('spreadsheet_id'), req_data.get('sheet_name'), req_data.get('assigned_users', [])
    if not all([spreadsheet_id, sheet_name]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        all_rows = permissions_worksheet.get_all_values()
        rows_to_delete_indices = [i + 1 for i, row in enumerate(all_rows) if len(row) > 1 and row[0] == spreadsheet_id and row[1] == sheet_name]
        if rows_to_delete_indices:
            for index in sorted(rows_to_delete_indices, reverse=True):
                permissions_worksheet.delete_rows(index)

        if assigned_users:
             permissions_worksheet.append_rows([[spreadsheet_id, sheet_name, user] for user in assigned_users], value_input_option='USER_ENTERED')
        else:
             permissions_worksheet.append_row([spreadsheet_id, sheet_name, ""])

        return jsonify({"success": True, "message": f"Permissions for '{sheet_name}' updated."})
    except Exception as e: return jsonify({"success": False, "message": f"Failed to set permissions: {e}"}), 500

# --- 9. RUN THE FLASK APP ---
if __name__ == '__main__':
    app.run(debug=True)