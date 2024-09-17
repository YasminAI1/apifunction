import logging

#adapt this coede for this function because azure

import azure.functions as func
from datetime import datetime
import os
import re
import requests
import json
import urllib3
from datetime import datetime
from azure.core.credentials import AzureKeyCredential
from azure.ai.formrecognizer import DocumentAnalysisClient
import base64
import tempfile

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def process_file(recordid,base64_string,output_file_path):
    base64_to_file(base64_string, output_file_path)
    # Decodificar la cadena base64 a binario
    file_path = output_file_path
    
    # Load the model
    endpoint = "https://testforintegration.cognitiveservices.azure.com/"
    key = "5c1e31c6c51f4abc9e23c760602f9f54"
    model_id = "LOP_Model_CU"
    model = load_model(endpoint, key)

    # Process and extract data from the downloaded PDF
    field_names = ["onb_street", "onb_zip", "onb_city", "onb_state", "onb_claim_number", "onb_mail", "onb_policy_number", "onb_date_of_loss", "oab_date", "lop_date", "onb_street2", "lop_signed_by_hoh"]
    result = process_data(model, model_id, file_path)
    extracted_data = extract_data(result, field_names)

    # Get the token for API request
    login_url = "https://pdss.eastus.cloudapp.azure.com/webservice/Users/Login"
    token = consume_get_token(login_url, headers={
        "X-ENCRYPTED": "0",
        "x-api-key": "z2WYcMmWT8PTNT36mervcMBhc65bQ2Jy",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic U2FuZGJveDpGaldKTnhuOFRiS3oyTXo0YVJGUXZuZjhBcFBMdWc3Mg=="
    })

    if token:
        # Send the PUT request with the extracted data
        put_url = f"https://pdss.eastus.cloudapp.azure.com/webservice/Claims/Record/{recordid}"
        response = consume_put_api(put_url, token, extracted_data)
        if response:
            logging.info("PUT request response:", response)

        else:
            logging.info("PUT request failed.")
    else:
        logging.info("Failed to obtain token.")

def process_file_pdf(recordid,file_pdf, output_file_path):
    # Save the file to a temporary location
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, output_file_path)
    with open(file_path, 'wb') as f:
        f.write(file_pdf.stream.read())
    
    # Decodificar la cadena base64 a binario
    
    # Load the model
    endpoint = "https://testforintegration.cognitiveservices.azure.com/"
    key = "5c1e31c6c51f4abc9e23c760602f9f54"
    model_id = "LOP_Model_CU"
    model = load_model(endpoint, key)

    # Process and extract data from the downloaded PDF
    field_names = ["onb_street", "onb_zip", "onb_city", "   ", "onb_claim_number", "onb_mail", "onb_policy_number", "onb_date_of_loss", "oab_date", "lop_date", "onb_street2", "lop_signed_by_hoh"]
    result = process_data(model, model_id, file_path)
    extracted_data = extract_data(result, field_names)

    # Get the token for API request
    login_url = "https://pdss.eastus.cloudapp.azure.com/webservice/Users/Login"
    token = consume_get_token(login_url, headers={
        "X-ENCRYPTED": "0",
        "x-api-key": "z2WYcMmWT8PTNT36mervcMBhc65bQ2Jy",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic U2FuZGJveDpGaldKTnhuOFRiS3oyTXo0YVJGUXZuZjhBcFBMdWc3Mg=="
    })

    if token:
        # Send the PUT request with the extracted data
        put_url = f"https://pdss.eastus.cloudapp.azure.com/webservice/Claims/Record/{recordid}"
        response = consume_put_api(put_url, token, extracted_data)
        if response:
            logging.info("PUT request response:", response)

        else:
            logging.info("PUT request failed.")
    else:
        logging.info("Failed to obtain token.")

    if os.path.exists(file_path):
        os.remove(file_path)
        logging.info(f"Temporary file {file_path} deleted.")

#create a function for convert base64 file to pdf (receive by API ) 
def file_to_base64(file_path):
    # Abrir el archivo en modo binario
    with open(file_path, "rb") as file:
        # Leer el contenido del archivo y convertirlo a base64
        encoded_string = base64.b64encode(file.read()).decode('utf-8')
    return encoded_string

def base64_to_file(base64_string, output_file_path):
    # Decodificar la cadena base64 a binario
    with open(output_file_path, "wb") as file:
        file.write(base64.b64decode(base64_string))

def load_model(endpoint, key):
    document_analysis_client = DocumentAnalysisClient(endpoint=endpoint, credential=AzureKeyCredential(key))
    return document_analysis_client

def process_data(model, model_id, document_path):
    try:
        with open(document_path, "rb") as f:
            poller = model.begin_analyze_document(model_id=model_id, document=f)
            result = poller.result()
            return result
        
    except Exception as e:
        logging.error(f"Error processing data: {e}")
        return None

def extract_data(result, field_names):
    field_dict = {field: "" for field in field_names}
    for document in result.documents:
        for name, field in document.fields.items():
            field_value = field.value if field.value else field.content

            if "date" in  name and field_value is not None:
                field_value = field_value.replace("/", "-")
                               
            if name in field_dict:
                field_dict[name] = field_value if field_value is not None else ""
    logging.info("Field Dict:", field_dict)
    return field_dict
    
def authenticate_google_drive(removed):  # Removed as not used in this version
    pass

def consume_get_token(url, headers=None):
    try:
        data = {
            "userName": "Sandbox",
            "password": "SandboxAPI2023!Aug"
        }
        response = requests.post(url, headers=headers, data=data, verify=False)
        if response.status_code == 200:
            response_data = response.json()
            token = response_data.get('result', {}).get('token')
            if token:
                return token
            else:
                logging.info("Token not found in response.")
                return None
        else:
            logging.info(f"Error: Login request failed with status code {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error: {e}")
        return None

def consume_put_api(url, token, data):
    try:
        headers = {
            "x-api-key": "z2WYcMmWT8PTNT36mervcMBhc65bQ2Jy",
            "x-token": token,
            "Content-Type": "application/json",
            "Authorization": "Basic U2FuZGJveDpGaldKTnhuOFRiS3oyTXo0YVJGUXZuZjhBcFBMdWc3Mg=="
        }
        response = requests.put(url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            logging.info("PUT request successful!")
            return response.json()
        else:
            logging.info(f"Error: PUT request failed with status code {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error: {e}")
        return None


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        file_pdf = req.files['file']
    except KeyError:
        return func.HttpResponse(
            "Please upload a file.",
            status_code=400
        )

    try:
        #req_body = req.get_json()
        recordid=req.form.get('recordid')

    except ValueError:
        logging.error(f"Error: {ValueError}")
        return func.HttpResponse(
        "No recordid found in the request.",
        status_code=400
        )

    else:
        
        #recordid = req_body.get('recordid')
        #file_base64 = req_body.get('file_base64')
        output_file_path_temp = "{}.pdf".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
        process_file_pdf(recordid, file_pdf, output_file_path_temp)
        #os.remove(output_file_path_temp)

    if True:
        #return func.HttpResponse({"process":"ok"})
        result = {
            #"file": df.describe().to_dict(),
            "recordid": recordid,
            "process": "ok"
        #I need to add in the response the extracted dat with the fields onb_street, onb_zip, onb_city, onb_state, onb_claim_number, onb_mail, onb_policy_number, onb_date_of_loss, oab_date, lop_date, onb_street2, lop_signed_by_hoh
        
            
        }

        # Return result as JSON
        return func.HttpResponse(json.dumps(result), mimetype="application/json")

    else:
        return func.HttpResponse(
             "Please pass a name on the query string or in the request body",
             status_code=400
        )