import streamlit as st
import pandas as pd
from tools import Crypt, GoogleDriveHandler
from streamlit_oauth import OAuth2Component
import base64
import json

# Customizing app
def customize():

    st.set_page_config(layout="wide", page_title='Encrypto', page_icon='🔒', menu_items=None)

    with open('assets/styles.css') as f:
        style = f'<style>{f.read()}</style>'
        st.markdown(style, unsafe_allow_html=True)

# Function to decrypt the passwords
def decrypt_file(df, key, salt):
    crypt = Crypt(key, salt)
    df = df.replace('',None)
    df.loc[:,'username'] = df['username'].apply(crypt.decrypt_password)
    df.loc[:,'password'] = df['password'].apply(crypt.decrypt_password)
    return df

# Function to encrypt the passwords
def encrypt_file(df, key):
    crypt = Crypt(key)
    df = df.replace('',None)
    df.loc[:,'username'] = df['username'].apply(crypt.encrypt_password)    
    df.loc[:,'password'] = df['password'].apply(crypt.encrypt_password)
    df = df.reset_index()
    df = pd.concat( [df, pd.DataFrame({'usage':'salt','username':'','password':crypt.salt.decode()}, index=['0'])])
    return df


customize()
st.title("Encrypto 🔒", anchor=False)

def cleaning():
    keys = list(st.session_state.keys())
    for key in keys:
        st.session_state.pop(key)
    st.session_state.df = None

if 'df' not in st.session_state:
    cleaning()

container = st.container(border=True)
col1, col2, col3 = container.columns(3)
mode = col1.radio('Mode :', horizontal=True, options=['Google Drive','Local File'], on_change=cleaning)
holder = col3.empty()

if mode == 'Local File':
    file = holder.file_uploader("Upload CSV file", type=["csv"], label_visibility='collapsed')
    if file is not None:
        st.session_state.df = pd.read_csv(file, usecols=['usage','username','password'], index_col='usage')

# Initialize session state 
if 'checkbox_checked' not in st.session_state:
    st.session_state.checkbox_checked = False

# Checkbox control
new = col2.checkbox('Start New')

if new:
    # Update the flag in session state when checkbox is checked
    st.session_state.checkbox_checked = True
    
    # Conditions to initialize the DataFrame
    if ("auth" in st.session_state and mode == 'Google Drive') or mode == 'Local File':
        st.session_state.df = pd.DataFrame(columns=['usage', 'username', 'password'])
else:
    # Call cleaning function if checkbox has been checked before
    if st.session_state.checkbox_checked:
        cleaning()
        st.session_state.checkbox_checked = False


if mode=='Google Drive':

    # OAuth2 Configuration
    CLIENT_ID = st.secrets["google_drive"]["CLIENT_ID"]
    CLIENT_SECRET = st.secrets["google_drive"]["CLIENT_SECRET"]

    AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

    # OAuth2 Flow
    with col3:
        if "auth" not in st.session_state:
            oauth2 = OAuth2Component(CLIENT_ID, CLIENT_SECRET, AUTHORIZE_ENDPOINT, TOKEN_ENDPOINT, REVOKE_ENDPOINT)
            result = oauth2.authorize_button(
                name="Continue with Google",
                icon="https://www.google.com.tw/favicon.ico",
                redirect_uri="https://encrypto.streamlit.app/component/streamlit_oauth.authorize_button",
                scope="openid email profile https://www.googleapis.com/auth/drive.file",
                key="google",
                extras_params={"prompt": "consent", "access_type": "offline"},
                use_container_width=True,
                pkce='S256'
            )

            if result:
                # Decode the id_token and get the user's email address
                id_token = result["token"]["id_token"]
                payload = id_token.split(".")[1]
                payload += "=" * (-len(payload) % 4)  # Add padding
                payload = json.loads(base64.b64decode(payload))
                st.session_state["auth"] = payload["email"]
                st.session_state["token"] = result["token"]
                st.rerun()

if "auth" in st.session_state and not new and not isinstance(st.session_state.df, pd.DataFrame):
        
        token = st.session_state["token"]
        drive_handler = GoogleDriveHandler(token, CLIENT_ID, CLIENT_SECRET)

        # Read a file from Google Drive
        df = drive_handler.read_file_from_drive()
        df.set_index('usage',inplace= True)
        st.session_state.df = df

if isinstance(st.session_state.df, pd.DataFrame):
    holder.empty()
    key = col3.text_input("Insert Key :", key='key')
    
    if key:

        if st.session_state.df.empty:
            if 'session_salt' not in st.session_state :
                crypt = Crypt(key)
                st.session_state.session_salt = crypt.salt.decode()

            st.session_state.df = pd.concat( [st.session_state.df, pd.DataFrame({'usage':'salt','username':'','password':st.session_state.session_salt}, index=['0'])])
            st.session_state.df.set_index('usage',inplace= True)
        
        try:                    
            salt = st.session_state.df.filter(items=['salt'], axis=0).values[0][1].encode()
        except Exception as e:
            st.error('Salt not found.')
        else:
            try:
                temp = st.session_state.df[st.session_state.df.index != 'salt']
                decrypted_df = decrypt_file(temp, key, salt)
                decrypted_df = st.data_editor(decrypted_df, num_rows='dynamic', use_container_width=True)
            except:
                st.error('Wrong password.')
            else:

                def convert_df(decrypted_df):
                    encrypted_df = encrypt_file(decrypted_df, key)
                    res = encrypted_df.to_csv(index=False).encode('utf-8')
                    return res
                
                try:
                    csv = convert_df(decrypted_df)
                    if mode == 'Local File':
                        csv = convert_df(decrypted_df)
                        if st.download_button(
                            label="Encrypt",
                            data=csv,
                            file_name='encrypto.csv',
                            mime='text/csv',
                            use_container_width=True
                            ):
                            st.success('File downloaded successfully', icon="✅")

                    # Save DataFrame as CSV to Google Drive
                    if mode == 'Google Drive' and "auth" in st.session_state and st.button('Upload to Goodle Drive', use_container_width=True):
                            
                        token = st.session_state["token"]
                        drive_handler = GoogleDriveHandler(token, CLIENT_ID, CLIENT_SECRET)
                        file_id = drive_handler.save_binary_to_drive(csv)
                        st.success('File uploaded successfully', icon="✅")


                except Exception as e:
                    st.error(f'Please fill both `username` and `password` fields.')   
    elif not key:
        st.warning('Key is needed.')             