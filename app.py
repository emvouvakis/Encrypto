import streamlit as st
import pandas as pd
from tool import Crypt

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
    st.session_state.df = None
    st.session_state.key = None

if 'df' not in st.session_state:
    cleaning()

container = st.container(border=True)
col1, col2 = container.columns(2)
mode = col1.radio('Mode :', horizontal=True, options=['Local File','Start New'], on_change=cleaning)
holder = col2.empty()

if mode == 'Local File':
    file = holder.file_uploader("Upload CSV file", type=["csv"], label_visibility='collapsed')
    if file is not None:
        st.session_state.df = pd.read_csv(file, usecols=['usage','username','password'], index_col='usage')
else:
    st.session_state.df = pd.DataFrame(columns=['usage','username','password']) 

if isinstance(st.session_state.df, pd.DataFrame):
    holder.empty()
    key = col2.text_input("Insert Key :", key='key')
    
    if key:

        if st.session_state.df.empty:
            crypt = Crypt(key)
            st.session_state.df = pd.concat( [st.session_state.df, pd.DataFrame({'usage':'salt','username':'','password':crypt.salt.decode()}, index=['0'])])
            st.session_state.df.set_index('usage',inplace= True)
        
        try:
            salt = st.session_state.df.filter(items=['salt'], axis=0).values[0][1].encode()
        except:
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
                    st.download_button(
                        label="Encrypt",
                        data=csv,
                        file_name='encrypto.csv',
                        mime='text/csv',
                        use_container_width=True
                        )

                except:
                    st.error('Please fill both `username` and `password` fields.')                