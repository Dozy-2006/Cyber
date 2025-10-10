import gspread
from oauth2client.service_account import ServiceAccountCredentials
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import json
from datetime import datetime
import re
import pandas as pd
from gspread_dataframe import set_with_dataframe
import gspread.utils

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
    print("Successfully connected to Google Sheets.")
except Exception as e:
    print(f"An unexpected error occurred during setup: {e}")
    exit()

# --- 3. HELPER FUNCTIONS ---

def is_valid_date(date_string):
    if not date_string: return True
    try:
        datetime.strptime(str(date_string), '%Y-%m-%d')
        return True
    except (ValueError, TypeError):
        return False

def apply_autocorrect(data_dict, schema):
    """Implicitly cleans data based on field type."""
    corrected_data = data_dict.copy()
    schema_map = {field.get('name'): field for field in schema}

    for field_name, value in corrected_data.items():
        rule = schema_map.get(field_name)
        if not rule or value is None:
            continue
        
        value_str = str(value).strip()
        
        # Apply uppercase autocorrect for specific types
        if rule.get('type') in ['pan', 'vehicle_number']:
            value_str = value_str.upper()
        elif rule.get('type') == 'time_12hr':
             value_str = value_str.upper()

        corrected_data[field_name] = value_str

        if rule.get('type') == 'date' and value_str:
            try:
                corrected_date = pd.to_datetime(value_str, errors='coerce')
                if pd.notna(corrected_date):
                    corrected_data[field_name] = corrected_date.strftime('%Y-%m-%d')
            except Exception:
                pass 
                
    return corrected_data

def validate_case_data(case_data, schema):
    for field in schema:
        field_name = field.get('name')
        value = case_data.get(field_name)
        value_str = str(value or '').strip()

        is_required = field.get('required')
        if (is_required is True or str(is_required).lower() == 'true') and not value_str:
            return f"'{field_name}' is a required field and cannot be empty."

        if not value_str: continue

        field_type = field.get('type')
        length = field.get('length')
        fmt = field.get('format')
        is_fixed_raw = field.get('isFixed', False)
        is_fixed = is_fixed_raw is True or str(is_fixed_raw).lower() == 'true'

        if field_type == 'date':
            if not is_valid_date(value_str):
                return f"Invalid date format for '{field_name}'. Use YYYY-MM-DD."
        elif field_type == 'year':
            if not (value_str.isdigit() and len(value_str) == 4):
                return f"'{field_name}' must be a 4-digit Year."
        elif field_type == 'pincode':
            if not (value_str.isdigit() and len(value_str) == 6):
                return f"'{field_name}' must be a 6-digit Pincode."
        elif field_type == 'phone_number':
            if not (value_str.isdigit() and len(value_str) == 10):
                return f"'{field_name}' must be a 10-digit Phone Number."
        elif field_type == 'aadhar':
            if not (value_str.isdigit() and len(value_str) == 12):
                return f"'{field_name}' must be a 12-digit Aadhar Number."
        elif field_type == 'police_number':
            if not (value_str.isdigit() and 3 <= len(value_str) <= 4):
                return f"'{field_name}' must be a 3 or 4-digit Police Number."
        elif field_type == 'pan':
            if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', value_str.upper()):
                return f"'{field_name}' is not a valid PAN format."
        elif field_type == 'vehicle_number':
            if not re.match(r'^[A-Z]{2}[0-9]{1,2}[A-Z]{1,2}[0-9]{4}$', value_str.upper()):
                return f"'{field_name}' is not a valid Vehicle Number format (e.g., TN01AB1234)."
        elif field_type == 'time_24hr':
            if not re.match(r'^([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?$', value_str):
                return f"'{field_name}' is not a valid 24-hour time format (HH:MM)."
        elif field_type == 'time_12hr':
            if not re.match(r'^(0?[1-9]|1[0-2]):([0-5]\d)(?::([0-5]\d))?\s?[AP]M$', value_str.upper()):
                return f"'{field_name}' is not a valid 12-hour time format (e.g., 01:30 PM)."
        elif field_type == 'latitude_tn':
            try:
                lat = float(value_str)
                if not (8.0 <= lat < 14.0):
                    return f"'{field_name}' must be a latitude value between 8.0 and 13.99..."
                if len(value_str.split('.')[1]) < 5:
                    return f"'{field_name}' must have at least 5 decimal places."
            except (ValueError, IndexError):
                return f"'{field_name}' is not a valid decimal latitude."
        elif field_type == 'longitude_tn':
            try:
                lon = float(value_str)
                if not (76.0 <= lon < 81.0):
                    return f"'{field_name}' must be a longitude value between 76.0 and 80.99..."
                if len(value_str.split('.')[1]) < 5:
                    return f"'{field_name}' must have at least 5 decimal places."
            except (ValueError, IndexError):
                return f"'{field_name}' is not a valid decimal longitude."
        elif field_type == 'decimal_latlon': # Generic decimal
            if not re.match(r'^\d{1,3}\.\d+$', value_str):
                return f"'{field_name}' must be a decimal value (e.g., 12.3456)."
        elif fmt:
            regex_parts = []
            for char in fmt:
                if char == '_':
                    regex_parts.append(r'\d' if field_type == 'number' else r'.')
                else:
                    regex_parts.append(re.escape(char))
            regex_pattern = '^' + ''.join(regex_parts) + '$'
            if not re.match(regex_pattern, value_str):
                return f"'{field_name}' value '{value_str}' does not match format '{fmt}'."
        elif field_type == 'number':
            if not value_str.isdigit():
                 return f"'{field_name}' must contain only digits."
            numeric_val = re.sub(r'[^\d]', '', value_str)
            if length:
                try:
                    length = int(length)
                    if is_fixed and len(numeric_val) != length:
                        return f"'{field_name}' must be exactly {length} digits long."
                    if not is_fixed and len(numeric_val) > length:
                        return f"'{field_name}' cannot be more than {length} digits long."
                except (ValueError, TypeError): pass
        elif field_type == 'text':
            if length:
                try:
                    length = int(length)
                    if len(value_str) > length:
                        return f"'{field_name}' cannot be more than {length} characters long."
                except (ValueError, TypeError): pass

    return None

# --- 4. AUTHENTICATION & USER MANAGEMENT ---
@app.route('/login', methods=['POST'])
def authenticateUser():
    login_data = request.get_json()
    role = login_data.get('role', '').strip().lower(); username = login_data.get('username', '').strip(); password = login_data.get('password', '')
    if not all([role, username, password]): return jsonify({"success": False, "message": "Missing required fields"}), 400
    
    for user_record in users_worksheet.get_all_records():
        user = {k.strip().lower(): v.strip() if isinstance(v, str) else v for k, v in user_record.items()}
        
        if user.get('username', '').lower() == username.lower() and user.get('role', '').lower() == role:
            password_key = next((k for k in user_record if k.strip().lower() == 'hashedpassword'), None)
            if not password_key: continue

            if check_password_hash(user_record[password_key], password):
                print(f"Successful login for user: {username}")
                original_user_data = {k.strip():v for k,v in user_record.items()}
                user_details = { "username": original_user_data.get('Username'), "role": original_user_data.get('Role'), "accessScope": original_user_data.get('AccessScope'), "gender": original_user_data.get('Gender') }
                return jsonify({"success": True, "user": user_details})
    
    print(f"Failed login attempt for user: {username}")
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/admin/get-all-users', methods=['GET'])
def get_all_users():
    try:
        users = users_worksheet.get_all_records()
        users_to_return = [{k: v for k, v in u.items() if k.strip().lower() != 'hashedpassword'} for u in users]
        return jsonify({"success": True, "users": users_to_return})
    except Exception as e: return jsonify({"success": False, "message": f"Could not fetch users: {e}"}), 500

@app.route('/admin/add-user', methods=['POST'])
def add_user():
    req_data = request.get_json()
    username = req_data.get('username','').strip(); password = req_data.get('password',''); role = req_data.get('role','').strip()
    access_scope = req_data.get('accessScope', 'all').strip(); gender = req_data.get('gender','').strip(); station = req_data.get('station','').strip()
    if not all([username, password, role, gender, station]): return jsonify({"success": False, "message": "All fields are required."}), 400
    try:
        all_usernames = [str(u.get('Username', '')).strip().lower() for u in users_worksheet.get_all_records()]
        if username.lower() in all_usernames:
            return jsonify({"success": False, "message": f"User '{username}' already exists."}), 409
        
        hashed_password = generate_password_hash(password)
        new_user_row = [username, hashed_password, role, access_scope, gender, station]
        users_worksheet.append_row(new_user_row)
        return jsonify({"success": True, "message": f"User '{username}' created successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

@app.route('/admin/change-password', methods=['POST'])
def admin_change_password():
    req_data = request.get_json(); username = req_data.get('username','').strip(); new_password = req_data.get('new_password','')
    if not all([username, new_password]): return jsonify({"success": False, "message": "Username and new password are required."}), 400
    try:
        cell = users_worksheet.find(re.compile(f"^{re.escape(username)}$", re.IGNORECASE), in_column=1)
        if not cell: return jsonify({"success": False, "message": f"User '{username}' not found."}), 404
        
        headers = [h.strip().lower() for h in users_worksheet.row_values(1)]
        password_col_index = headers.index('hashedpassword') + 1
        new_hashed_password = generate_password_hash(new_password)
        users_worksheet.update_cell(cell.row, password_col_index, new_hashed_password)
        return jsonify({"success": True, "message": f"Password for '{username}' has been updated."})
    except Exception as e:
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

# --- 5. DATA FETCHING ---
@app.route('/get-data', methods=['POST'])
def getData():
    req_data = request.get_json(); user_data = req_data.get('user'); spreadsheet_id_override = req_data.get('spreadsheet_id')
    if not user_data: return jsonify({"success": False, "message": "User data not provided"}), 400
    role = user_data.get('role', '').strip().lower()
    
    if (role == 'sdo' or role == 'admin') and not spreadsheet_id_override:
        return jsonify({"success": True, "locations": master_worksheet.get_all_records()})
    
    spreadsheet_id = spreadsheet_id_override
    if not spreadsheet_id:
        access_scope = user_data.get('accessScope', '').strip()
        for loc in master_worksheet.get_all_records():
            if loc.get('LocationName', '').strip().lower() == access_scope.lower(): 
                spreadsheet_id = loc.get('Spreadsheet_ID')
                break
    
    if not spreadsheet_id: return jsonify({"success": False, "message": "Location not found"}), 404
    
    try:
        sheet = client.open_by_key(spreadsheet_id)
        all_tabs = [ws.title for ws in sheet.worksheets()]
        allowed_tabs = []
        
        schema_rules = {}
        for record in schema_worksheet.get_all_records():
            case_type_key = next((k for k in record if k.strip().lower() == 'casetype'), None)
            female_only_key = next((k for k in record if k.strip().lower() == 'isfemaleonly'), None)
            if not case_type_key: continue
            schema_rules[record[case_type_key]] = record.get(female_only_key, 'FALSE')

        for tab_name in all_tabs:
            rule = schema_rules.get(tab_name, 'FALSE')
            is_female_only = str(rule).strip().upper() == 'TRUE'
            
            user_gender = str(user_data.get('gender', '')).strip().lower()
            if is_female_only and user_gender != 'female':
                continue
            
            allowed_tabs.append(tab_name)
            
        return jsonify({"success": True, "spreadsheet_id": spreadsheet_id, "allowed_tabs": allowed_tabs})
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not access spreadsheet: {e}"}), 500

@app.route('/get-sheet-data', methods=['POST'])
def get_sheet_data():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); tab_name = req_data.get('tab_name'); search_query = req_data.get('search_query', '').lower().strip()
    if not all([spreadsheet_id, tab_name]): return jsonify({"success": False, "message": "Missing required data"}), 400
    
    try:
        sheet = client.open_by_key(spreadsheet_id); worksheet = sheet.worksheet(tab_name)
        
        all_values = worksheet.get_all_values()
        if not all_values or len(all_values) < 2:
            return jsonify({"success": True, "data": [], "headers": all_values[0] if all_values else [], "schema": []})

        headers = all_values[0]
        data_rows = all_values[1:]
        
        all_data = []
        for row in data_rows:
            if not any(row): continue
            record = {headers[i]: row[i] if i < len(row) else "" for i in range(len(headers))}
            all_data.append(record)

        schema = []
        try:
            for s in schema_worksheet.get_all_records():
                if s.get('CaseType', '').strip().lower() == tab_name.lower():
                    schema_json_key = next((k for k in s if k.strip().lower() == 'schemajson'), None)
                    if schema_json_key:
                        schema = json.loads(s[schema_json_key])
                    break
        except Exception as schema_error:
            print(f"Could not load/parse schema for {tab_name}: {schema_error}")
        
        if search_query:
            all_data = [row for row in all_data if any(str(v).lower().strip().find(search_query) != -1 for v in row.values())]
        
        return jsonify({"success": True, "data": all_data, "headers": headers, "schema": schema})
    except gspread.exceptions.WorksheetNotFound: return jsonify({"success": False, "message": f"Tab '{tab_name}' not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500
        
# --- 6. DATA MODIFICATION ---
@app.route('/add-case', methods=['POST'])
def add_case():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); tab_name = req_data.get('tab_name'); case_data = req_data.get('case_data'); should_validate = req_data.get('should_validate', True)
    if not all([spreadsheet_id, tab_name, case_data]): return jsonify({"success": False, "message": "Missing required data"}), 400
    
    try:
        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('CaseType', '').strip().lower() == tab_name.lower(): 
                schema_json_key = next((k for k in s if k.strip().lower() == 'schemajson'), None)
                if schema_json_key: schema = json.loads(s[schema_json_key])
                break
        
        corrected_case_data = apply_autocorrect(case_data, schema)

        if should_validate:
            error_message = validate_case_data(corrected_case_data, schema)
            if error_message: return jsonify({"success": False, "message": error_message}), 400
        
        sheet = client.open_by_key(spreadsheet_id); worksheet = sheet.worksheet(tab_name)
        headers = worksheet.row_values(1)
        case_id_header = next((h for h in headers if h.lower() == 'caseid'), None)

        if not case_id_header:
            return jsonify({"success": False, "message": "Cannot add case: 'CaseID' column not found."}), 500

        new_case_id = corrected_case_data.get(case_id_header)
        if not new_case_id:
             return jsonify({"success": False, "message": f"'{case_id_header}' cannot be empty."}), 400

        existing_case_ids = set(worksheet.col_values(headers.index(case_id_header) + 1)[1:])
        if new_case_id in existing_case_ids:
            return jsonify({"success": False, "message": f"'{case_id_header}' '{new_case_id}' already exists."}), 409
        
        new_row = [corrected_case_data.get(header, "") for header in headers]
        worksheet.append_row(new_row)
        return jsonify({"success": True, "message": "Case added successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to add case: {e}"}), 500

@app.route('/edit-case', methods=['POST'])
def edit_case():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); tab_name = req_data.get('tab_name'); case_id = req_data.get('case_id'); new_data = req_data.get('new_data'); should_validate = req_data.get('should_validate', True)
    if not all([spreadsheet_id, tab_name, case_id, new_data]): return jsonify({"success": False, "message": "Missing required data"}), 400

    schema = []
    for s in schema_worksheet.get_all_records():
        if s.get('CaseType', '').strip().lower() == tab_name.lower(): 
            schema_json_key = next((k for k in s if k.strip().lower() == 'schemajson'), None)
            if schema_json_key: schema = json.loads(s[schema_json_key])
            break
            
    corrected_data = apply_autocorrect(new_data, schema)

    if should_validate:
        error_message = validate_case_data(corrected_data, schema)
        if error_message: return jsonify({"success": False, "message": error_message}), 400

    try:
        sheet = client.open_by_key(spreadsheet_id); worksheet = sheet.worksheet(tab_name); 
        cell = worksheet.find(str(case_id))
        if not cell: return jsonify({"success": False, "message": "CaseID not found"}), 404
        headers = worksheet.row_values(1)
        updated_row = [corrected_data.get(header, "") for header in headers]
        worksheet.update(f'A{cell.row}:{chr(ord("A")+len(headers)-1)}{cell.row}', [updated_row])
        return jsonify({"success": True, "message": "Case updated successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to update case: {e}"}), 500

@app.route('/bulk-add-cases', methods=['POST'])
def bulk_add_cases():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); tab_name = req_data.get('tab_name'); cases_data = req_data.get('cases_data'); should_validate = req_data.get('should_validate', True)
    if not all([spreadsheet_id, tab_name, cases_data]): return jsonify({"success": False, "message": "Missing required data for bulk add."}), 400
    if not isinstance(cases_data, list) or len(cases_data) == 0: return jsonify({"success": False, "message": "No cases provided for bulk add."}), 400

    try:
        sheet = client.open_by_key(spreadsheet_id); worksheet = sheet.worksheet(tab_name); headers = worksheet.row_values(1)
        case_id_header = next((h for h in headers if h.lower() == 'caseid'), None)
        if not case_id_header:
            return jsonify({"success": False, "message": "Cannot add cases: 'CaseID' column not found."}), 500

        existing_case_ids = set(worksheet.col_values(headers.index(case_id_header) + 1)[1:])
        incoming_case_ids = set()
        
        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('CaseType', '').strip().lower() == tab_name.lower(): 
                schema_json_key = next((k for k in s if k.strip().lower() == 'schemajson'), None)
                if schema_json_key: schema = json.loads(s[schema_json_key])
                break
        
        corrected_and_validated_cases = []
        for i, case_data in enumerate(cases_data):
            corrected_case = apply_autocorrect(case_data, schema)
            
            current_case_id = corrected_case.get(case_id_header)
            if not current_case_id:
                return jsonify({"success": False, "message": f"Validation failed at row {i+2}: '{case_id_header}' cannot be empty."}), 400
            if current_case_id in existing_case_ids or current_case_id in incoming_case_ids:
                return jsonify({"success": False, "message": f"Validation failed at row {i+2}: Duplicate '{case_id_header}' '{current_case_id}' found."}), 409
            incoming_case_ids.add(current_case_id)
            
            if should_validate:
                error_message = validate_case_data(corrected_case, schema)
                if error_message: return jsonify({"success": False, "message": f"Validation failed at row {i+2}: {error_message}"}), 400
            
            corrected_and_validated_cases.append(corrected_case)

        rows_to_append = []
        for case in corrected_and_validated_cases:
            new_row = [case.get(header, "") for header in headers]
            rows_to_append.append(new_row)
        
        if rows_to_append:
            worksheet.append_rows(rows_to_append)
        return jsonify({"success": True, "message": f"{len(rows_to_append)} cases added successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to add bulk cases: {e}"}), 500

@app.route('/delete-case', methods=['POST'])
def delete_case():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); tab_name = req_data.get('tab_name'); case_id = req_data.get('case_id')
    if not all([spreadsheet_id, tab_name, case_id]): return jsonify({"success": False, "message": "Missing required data"}), 400
    try:
        sheet = client.open_by_key(spreadsheet_id); worksheet = sheet.worksheet(tab_name); cell = worksheet.find(str(case_id))
        if not cell: return jsonify({"success": False, "message": "CaseID not found"}), 404
        worksheet.delete_rows(cell.row)
        return jsonify({"success": True, "message": "Case permanently deleted."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to delete case: {e}"}), 500

# --- 7. ADMIN & VALIDATION ENDPOINTS ---
@app.route('/validate-and-format-sheet', methods=['POST'])
def validate_and_format_sheet():
    req_data = request.get_json()
    spreadsheet_id = req_data.get('spreadsheet_id')
    tab_name = req_data.get('tab_name')
    if not all([spreadsheet_id, tab_name]):
        return jsonify({"success": False, "message": "Spreadsheet ID and tab name are required."}), 400

    try:
        sheet = client.open_by_key(spreadsheet_id)
        worksheet = sheet.worksheet(tab_name)
        all_data = worksheet.get_all_values()
        if not all_data: 
            return jsonify({"success": True, "message": "Sheet is empty, nothing to do."})
        
        headers = [h.strip() for h in all_data[0]]
        df = pd.DataFrame(all_data[1:], columns=headers).dropna(how='all')
        if df.empty:
            return jsonify({"success": True, "message": "Sheet contains no data rows, nothing to do."})
        
        schema = []
        for s in schema_worksheet.get_all_records():
            if s.get('CaseType', '').strip().lower() == tab_name.lower():
                schema_json_key = next((k for k in s if k.strip().lower() == 'schemajson'), None)
                if schema_json_key: schema = json.loads(s[schema_json_key])
                break
        
        if not schema:
            return jsonify({"success": False, "message": f"No schema found for '{tab_name}'."}), 404

        df_copy = df.copy()
        error_df = pd.DataFrame(False, index=df.index, columns=df.columns)
        
        schema_map = {field.get('name'): field for field in schema}

        for index, row in df.iterrows():
            row_dict = row.to_dict()
            corrected_row = apply_autocorrect(row_dict, schema)
            df_copy.loc[index] = pd.Series(corrected_row)

        for index, row in df_copy.iterrows():
            row_dict = row.to_dict()
            for field_name, value in row_dict.items():
                if field_name not in headers: continue # Skip if field is not a column
                rule = schema_map.get(field_name)
                if not rule: continue
                
                error_msg = validate_case_data({field_name: value}, [rule])
                
                if error_msg:
                    error_df.at[index, field_name] = True

        df_copy.fillna('', inplace=True)
        
        worksheet.clear()
        set_with_dataframe(worksheet, df_copy, include_index=False, row=1, col=1)

        error_cells_a1 = []
        for r_idx, row in error_df.iterrows():
            if r_idx not in df.index: continue
            for c_name, is_error in row.items():
                if is_error:
                    sheet_row = df.index.get_loc(r_idx) + 2
                    try:
                        sheet_col = headers.index(c_name) + 1
                        error_cells_a1.append(gspread.utils.rowcol_to_a1(sheet_row, sheet_col))
                    except ValueError:
                        print(f"Warning: Column '{c_name}' from error check not found in sheet headers.")

        
        if error_cells_a1:
            # Darker, "thicker" red color
            RED_FORMAT = { "backgroundColor": {"red": 0.9, "green": 0.2, "blue": 0.2}, }
            worksheet.format(error_cells_a1, RED_FORMAT)
        
        return jsonify({
            "success": True, 
            "message": f"Sheet '{tab_name}' validated and formatted. {len(error_cells_a1)} errors found and highlighted.",
            "error_cells": error_cells_a1
        })

    except gspread.exceptions.WorksheetNotFound:
        return jsonify({"success": False, "message": f"Tab '{tab_name}' not found."}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {e}"}), 500


@app.route('/admin/get-sheets-for-location', methods=['POST'])
def get_sheets_for_location():
    req_data = request.get_json()
    spreadsheet_id = req_data.get('spreadsheet_id')
    if not spreadsheet_id: return jsonify({"success": False, "message": "Spreadsheet ID is required."}), 400
    try:
        spreadsheet = client.open_by_key(spreadsheet_id)
        sheet_names = [worksheet.title for worksheet in spreadsheet.worksheets()]
        return jsonify({"success": True, "sheet_names": sheet_names})
    except gspread.exceptions.SpreadsheetNotFound:
        return jsonify({"success": False, "message": "Spreadsheet not found. Check the ID and permissions."}), 404
    except Exception as e: return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

@app.route('/admin/delete-sheet', methods=['POST'])
def delete_sheet_endpoint():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); sheet_name = req_data.get('sheet_name')
    if not all([spreadsheet_id, sheet_name]): return jsonify({"success": False, "message": "Spreadsheet ID and sheet name are required."}), 400
    try:
        spreadsheet = client.open_by_key(spreadsheet_id); worksheet_to_delete = spreadsheet.worksheet(sheet_name)
        spreadsheet.del_worksheet(worksheet_to_delete)
        try:
            cell = schema_worksheet.find(re.compile(f"^{re.escape(sheet_name)}$", re.IGNORECASE))
            if cell: schema_worksheet.delete_rows(cell.row)
        except gspread.exceptions.CellNotFound:
            print(f"Info: Schema for deleted sheet '{sheet_name}' not found.")
        return jsonify({"success": True, "message": f"Sheet '{sheet_name}' has been deleted."})
    except gspread.exceptions.WorksheetNotFound:
        return jsonify({"success": False, "message": f"Sheet '{sheet_name}' not found."}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

@app.route('/add-sheet', methods=['POST'])
def add_sheet_endpoint():
    req_data = request.get_json(); spreadsheet_id = req_data.get('spreadsheet_id'); sheet_name = req_data.get('sheet_name', '').strip(); schema = req_data.get('schema'); is_female_only = req_data.get('isFemaleOnly', False)
    if not all([spreadsheet_id, sheet_name, schema]): return jsonify({"success": False, "message": "Missing required data."}), 400
    if not isinstance(schema, list) or len(schema) == 0: return jsonify({"success": False, "message": "Schema must define at least one column."}), 400
    try:
        headers = []
        for field in schema:
            if 'name' not in field or not field['name'].strip(): return jsonify({"success": False, "message": "All columns must have a non-empty name."}), 400
            headers.append(field['name'].strip())
        if len(headers) != len(set(headers)): return jsonify({"success": False, "message": "Column names must be unique."}), 400
        
        spreadsheet = client.open_by_key(spreadsheet_id)
        existing_sheets = [s.title.lower().strip() for s in spreadsheet.worksheets()]
        if sheet_name.lower() in existing_sheets:
            return jsonify({"success": False, "message": f"A sheet named '{sheet_name}' already exists."}), 409
            
        worksheet = spreadsheet.add_worksheet(title=sheet_name, rows="100", cols=len(headers))
        worksheet.append_row(headers)
        schema_worksheet.append_row([sheet_name, json.dumps(schema), str(is_female_only).upper()])
        return jsonify({"success": True, "message": f"Sheet '{sheet_name}' created successfully."})
    except Exception as e:
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500
    
@app.route('/add-location', methods=['POST'])
def add_location():
    req_data = request.get_json(); location_name = req_data.get('location_name','').strip(); spreadsheet_id = req_data.get('spreadsheet_id','').strip()
    if not all([location_name, spreadsheet_id]): return jsonify({"success": False, "message": "Missing required data."}), 400
    try:
        for loc in master_worksheet.get_all_records():
            if loc.get('LocationName', '').strip().lower() == location_name.lower() or loc.get('Spreadsheet_ID') == spreadsheet_id:
                    return jsonify({"success": False, "message": "This location or ID already exists."}), 409
        master_worksheet.append_row([location_name, spreadsheet_id])
        return jsonify({"success": True, "message": "New location registered successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"An internal server error occurred: {e}"}), 500

# --- 8. RUN THE FLASK APP ---
if __name__ == '__main__':
    app.run(debug=True)