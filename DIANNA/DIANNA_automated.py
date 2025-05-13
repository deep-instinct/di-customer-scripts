import os
import requests
import base64
import time

#This script will take the requested input for D-Appliance URL, API Token and path the file you want to analyze. It will then submit the file for analysis and automatically poll the result and provide back the json response.

key = input('API Key: ')
fqdn = input('D-Appliance: ')

def upload_rest_api_file_in_chunks(filepath, url, chunk_size=4*1024*1024):
    filename = os.path.basename(filepath)
    total_size = os.path.getsize(filepath)
    total_chunks = total_size // chunk_size + (1 if total_size % chunk_size else 0)
    response = None

    with open(filepath, 'rb') as file:
        for chunk_number in range(total_chunks):
            chunk = file.read(chunk_size)
            start_byte = chunk_size * chunk_number
            data = {
                'start_byte': start_byte,
                'end_byte': start_byte + len(chunk) - 1,
                'total_bytes': total_size,
                'upload_id': response.json()["upload_id"] if response is not None else None,
                'file_name': filename,
                'file_chunk': base64.b64encode(chunk).decode('utf-8'),
            }

            response = requests.post(url, json=data, headers={"Authorization": key}, verify=False)

            # Print the JSON response from the API
            try:
                json_response = response.json()
            except Exception as e:
                print(f"Failed to parse JSON response for chunk {chunk_number + 1}: {e}")
                print(f"Raw Response: {response.text}")

    return response.json() if response else None


def fetch_analysis_result(analysis_id, key):
    """
    Fetch the analysis result using the analysisID.
    """
    url = f'https://{fqdn}/api/v1/dianna/analysisResult/{analysis_id}'
    headers = {
        'accept': 'application/json',
        'Authorization': key,
    }

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        try:
            json_response = response.json()
            print("Analysis Result Response:", json_response)
            return json_response
        except Exception as e:
            print(f"Failed to parse JSON response: {e}")
            print(f"Raw Response: {response.text}")
            return None
    else:
        print(f"Request failed with status code: {response.status_code}")
        return None


if __name__ == '__main__':
    #Input path and file name
    filepath = input('File Path: ')
    rest_url = f'https://{fqdn}/api/v1/dianna/analyzeFile'
    
    #Upload the file in chunks
    final_response = upload_rest_api_file_in_chunks(filepath, rest_url)
    print("Final Response:", final_response)
    
    #Store analysisID from the final response
    analysis_id = final_response.get("analysisId") if final_response else None

    if analysis_id:
        print(f"Analysis ID: {analysis_id}")
        
        #Wait for 2 second before requesting result
        time.sleep(5)
        
        #Fetch the analysis result
        api_key = key 
        analysis_result = fetch_analysis_result(analysis_id, key)
    else:
        print("No analysisID found in the final response.")
