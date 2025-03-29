from fastapi import FastAPI, File, UploadFile
import json
import requests
app = FastAPI()


@app.post("/audio")
async def get_file(file: UploadFile):
    pass


@app.get("/yandex_login")  # Changed endpoint to avoid conflict, and made it a path.
async def yandex_login(code: str):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": "78f8ad51b5ca4fb289ccefb21f957bb5",  # Replace with your actual client ID
        "client_secret": "b6c9d88569184d07849ef1294f69bb13",  # Replace with your actual client secret
    }

    try:
        res = requests.post("https://oauth.yandex.ru/token", data=data)
        res.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        response_data = res.json()  # Deserialize JSON response using .json()
        access_token = response_data["access_token"]

        # Use headers for authorization.  Yandex requires the Authorization header.
        headers = {"Authorization": f"Bearer {access_token}"}
        info = requests.get("https://login.yandex.ru/info", headers=headers) # Corrected to GET and added headers
        info.raise_for_status()
        user_info = info.json()

        print(user_info)
        return user_info['id']

    except requests.exceptions.RequestException as e:
        print(f"An error occurred making the request: {e}")
        try:
            # Attempt to extract more specific error information from Yandex's response
            error_response = e.response.json() if e.response else str(e)
            return {"error": f"Request failed: {error_response}"}
        except (json.JSONDecodeError, AttributeError):  # Couldnt return a full response for some reason
            return {"error": str(e)}

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return {"error": "Invalid JSON response from Yandex"}
    except KeyError as e:
        print(f"Missing key in JSON response: {e}")
        return {"error": f"Missing key {e} in Yandex response"}


@app.get("/auth_url")
async def get_auth_url():
    return {
        "url": "https://oauth.yandex.ru/authorize?response_type=code&client_id=78f8ad51b5ca4fb289ccefb21f957bb5"  # Replace with your actual client ID
    }