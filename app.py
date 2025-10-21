import streamlit as st
import streamlit_authenticator as stauth
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

# Database Setup
conn = sqlite3.connect('cleardeals.db', check_same_thread=False)
c = conn.cursor()

# Create Tables if not exist
c.execute('''CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT, role TEXT, name TEXT, status TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS queries (id TEXT PRIMARY KEY, rm_email TEXT, customer_name TEXT, mobile TEXT, query_type TEXT, notes TEXT, raised_time TEXT, solved_time TEXT, deo_email TEXT, comment TEXT, attachment BLOB, status TEXT)''')
conn.commit()

# Hash Passwords
hasher = stauth.Hasher(['@ppLe#1B$'])
hashed_password = hasher.hash('@ppLe#1B$')  # Master Admin password

# Add Master Admin if not exists
c.execute("SELECT * FROM users WHERE email=?", ('contact@cleardeals.co.in',))
if not c.fetchone():
    c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", ('contact@cleardeals.co.in', hashed_password, 'admin', 'Master Admin', 'active'))
    conn.commit()

# Authentication Config
credentials = {
    'usernames': {}
}
users = c.execute("SELECT email, password, name FROM users").fetchall()
for email, pw, name in users:
    credentials['usernames'][email] = {'name': name, 'password': pw}
authenticator = stauth.Authenticate(credentials, 'cleardeals', 'key', cookie_expiry_days=30)

# Google Calendar Setup (Replace with your credentials file)
GOOGLE_CREDENTIALS_FILE = 'credentials.json'  # Upload this file to your app folder

def get_google_calendar_service():
    scopes = ['https://www.googleapis.com/auth/calendar']
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', scopes)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GOOGLE_CREDENTIALS_FILE, scopes)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('calendar', 'v3', credentials=creds)

# Send Email (Placeholder, replace with smtplib for real email)
def send_email(to, subject, body):
    st.write(f"Email sent to {to}: {subject} - {body}")  # Replace with actual send later

# Send WhatsApp (Disabled for now)
# def send_whatsapp(to, body):
#     st.write("WhatsApp skipped for now")  # Twilio removed

# Generate Query ID
def generate_query_id(mobile):
    now = datetime.now()
    last5 = mobile[-5:]
    date_str = now.strftime('%d%m%y')
    time_str = now.strftime('%H%M')
    return f"{last5}-{date_str}-{time_str}"

# Filter DataFrame by Date
def filter_by_date(df, option):
    today = datetime.now().date()
    if option == 'Today':
        return df[df['raised_time'].dt.date == today]
    elif option == 'Yesterday':
        return df[df['raised_time'].dt.date == today - timedelta(days=1)]
    elif option == 'Last 7 Days':
        return df[df['raised_time'].dt.date >= today - timedelta(days=7)]
    return df  # Custom handled separately

# Main App
st.title("Cleardeals Ticketing System")

if 'role' not in st.session_state:
    st.session_state.role = None

# Home Page with Login Buttons
if not st.session_state.get('authenticated', False):
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Master Admin Login"):
            st.session_state.role = 'admin'
    with col2:
        if st.button("DEO Login"):
            st.session_state.role = 'deo'
    with col3:
        if st.button("RM Login"):
            st.session_state.role = 'rm'

    # Signup for RM/DEO
    st.subheader("Sign Up (for RM/DEO)")
    signup_email = st.text_input("Email")
    signup_pw = st.text_input("Password", type='password')
    signup_role = st.selectbox("Role", ['rm', 'deo'])
    signup_name = st.text_input("Name")
    if st.button("Sign Up"):
        hashed_pw = stauth.Hasher([signup_pw]).hash(signup_pw)[0]
        c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?)", (signup_email, hashed_pw, signup_role, signup_name, 'pending'))
        conn.commit()
        st.success("Signup requested. Wait for Admin approval.")
        send_email('contact@cleardeals.co.in', 'New Signup', f"Approve {signup_email} as {signup_role}")

    # Login Form
    if st.session_state.role:
        name, authentication_status, username = authenticator.login('Login', 'main')
        if authentication_status:
            st.session_state.authenticated = True
            st.session_state.email = username
            user_role = c.execute("SELECT role FROM users WHERE email=?", (username,)).fetchone()[0]
            if user_role != st.session_state.role:
                st.error("Wrong role. Try again.")
                authenticator.logout('Logout', 'main')
            else:
                st.success(f"Welcome {name}")
        elif authentication_status == False:
            st.error('Username/password is incorrect')
        elif authentication_status is None:
            st.warning('Please enter your username and password')

else:
    role = st.session_state.role
    email = st.session_state.email

    # Sidebar Navigation
    with st.sidebar:
        st.title(f"{role.upper()} Dashboard")
        if role == 'rm':
            page = st.selectbox("Menu", ['Dashboard', 'Raised Queries', 'Solved Queries', 'Logout'])
        elif role == 'deo':
            page = st.selectbox("Menu", ['Raised Queries', 'Solved Queries', 'Analytics', 'Logout'])
        elif role == 'admin':
            page = st.selectbox("Menu", ['Raised Queries', 'Solved Queries', 'Analytics', 'Team', 'Logout'])

    if page == 'Logout':
        authenticator.logout('Logout', 'sidebar')
        st.session_state.authenticated = False
        st.session_state.role = None
        st.rerun()

    # Fetch Queries
    all_queries = pd.read_sql("SELECT * FROM queries", conn)
    all_queries['raised_time'] = pd.to_datetime(all_queries['raised_time'])
    all_queries['solved_time'] = pd.to_datetime(all_queries['solved_time'], errors='coerce')

    if role == 'rm':
        my_queries = all_queries[all_queries['rm_email'] == email]
        if page == 'Dashboard':
            st.write("Summary")
            st.write(f"Raised: {len(my_queries[my_queries['status'] == 'raised'])}")
            st.write(f"Solved: {len(my_queries[my_queries['status'] == 'solved'])}")

        elif page == 'Raised Queries':
            st.subheader("Raised Queries")
            date_filter = st.selectbox("Date Filter", ['All', 'Today', 'Yesterday', 'Last 7 Days', 'Custom'])
            filtered = filter_by_date(my_queries[my_queries['status'] == 'raised'], date_filter)
            if date_filter == 'Custom':
                start = st.date_input("Start")
                end = st.date_input("End")
                filtered = filtered[(filtered['raised_time'].dt.date >= start) & (filtered['raised_time'].dt.date <= end)]
            st.dataframe(filtered[['id', 'customer_name', 'mobile', 'query_type']])  # Add column filters later with aggrid if needed

            if st.button("Raise Query"):
                with st.form("Raise Query Form"):
                    prop_url = st.text_input("Property URL")
                    cust_name = st.text_input("Customer Name")
                    mobile = st.text_input("Customer Mobile (10 digits)", max_chars=10)
                    query_type = st.selectbox("Query Type", ['Update Property details', 'Update Property photo', 'Revise Property Price', 'Portal links not working', 'Re-upload property', 'Property Reel Status', 'Other'])
                    notes = st.text_area("Notes")
                    attachment = st.file_uploader("Attached")
                    submit = st.form_submit_button("Submit")
                    if submit and len(mobile) == 10:
                        qid = generate_query_id(mobile)
                        raised_time = datetime.now().isoformat()
                        attachment_data = attachment.read() if attachment else None
                        c.execute("INSERT INTO queries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                  (qid, email, cust_name, mobile, query_type, notes, raised_time, None, None, None, attachment_data, 'raised'))
                        conn.commit()
                        st.success(f"Query submitted: {qid}")
                        # Integrations
                        send_email(email, "Query Raised", f"ID: {qid}")
                        # send_whatsapp(mobile, f"Query {qid} raised")  # Skipped
                        service = get_google_calendar_service()
                        event = {'summary': f"Query {qid}", 'start': {'dateTime': raised_time}, 'end': {'dateTime': raised_time}}
                        service.events().insert(calendarId='primary', body=event).execute()

        elif page == 'Solved Queries':
            st.subheader("Solved Queries")
            date_filter = st.selectbox("Date Filter", ['All', 'Today', 'Yesterday', 'Last 7 Days', 'Custom'])
            filtered = filter_by_date(my_queries[my_queries['status'] == 'solved'], date_filter)
            if date_filter == 'Custom':
                start = st.date_input("Start")
                end = st.date_input("End")
                filtered = filtered[(filtered['solved_time'].dt.date >= start) & (filtered['solved_time'].dt.date <= end)]
            st.dataframe(filtered[['id', 'customer_name', 'mobile', 'query_type', 'solved_time', 'deo_email', 'comment']])
            selected_id = st.text_input("View Query ID")
            if selected_id:
                query = all_queries[all_queries['id'] == selected_id].iloc[0]
                st.write(query)
                if query['attachment']:
                    st.download_button("Download Attachment", query['attachment'])

    elif role == 'admin' or role == 'deo':
        if role == 'deo':
            assigned_queries = all_queries[(all_queries['deo_email'] == email) & (all_queries['status'] == 'raised')]
            solved_queries = all_queries[(all_queries['deo_email'] == email) & (all_queries['status'] == 'solved')]
        else:
            assigned_queries = all_queries[all_queries['status'] == 'raised']
            solved_queries = all_queries[all_queries['status'] == 'solved']

        if page == 'Raised Queries':
            st.subheader("Raised Queries")
            date_filter = st.selectbox("Date Filter", ['All', 'Today', 'Yesterday', 'Last 7 Days', 'Custom'])
            filtered = filter_by_date(assigned_queries, date_filter)
            if date_filter == 'Custom':
                start = st.date_input("Start")
                end = st.date_input("End")
                filtered = filtered[(filtered['raised_time'].dt.date >= start) & (filtered['raised_time'].dt.date <= end)]
            st.dataframe(filtered[['id', 'customer_name', 'mobile', 'query_type']])

            if role == 'admin':
                assign_id = st.text_input("Assign Query ID")
                deo_list = [u[0] for u in c.execute("SELECT email FROM users WHERE role='deo' AND status='active'").fetchall()]
                assign_deo = st.selectbox("Assign to DEO", deo_list)
                if st.button("Assign"):
                    c.execute("UPDATE queries SET deo_email=? WHERE id=?", (assign_deo, assign_id))
                    conn.commit()
                    st.success("Assigned")

            view_id = st.text_input("View/Open Query ID")
            if view_id and view_id in filtered['id'].values:
                query = filtered[filtered['id'] == view_id].iloc[0]
                st.write(query)
                if query['attachment']:
                    st.download_button("Download Attachment", query['attachment'])
                comment = st.text_area("Add Comment")
                if st.button("Solve"):
                    solved_time = datetime.now().isoformat()
                    solved_str = datetime.now().strftime('%d%m%y-%H%M')
                    c.execute("UPDATE queries SET solved_time=?, comment=?, status='solved' WHERE id=?", (solved_time, comment, view_id))
                    conn.commit()
                    st.success("Solved")
                    send_email(query['rm_email'], "Query Solved", f"ID: {view_id} - {comment}")
                    # send_whatsapp(query['mobile'], f"Query {view_id} solved")  # Skipped

        elif page == 'Solved Queries':
            st.subheader("Solved Queries")
            date_filter = st.selectbox("Date Filter", ['All', 'Today', 'Yesterday', 'Last 7 Days', 'Custom'])
            filtered = filter_by_date(solved_queries, date_filter)
            if date_filter == 'Custom':
                start = st.date_input("Start")
                end = st.date_input("End")
                filtered = filtered[(filtered['solved_time'].dt.date >= start) & (filtered['solved_time'].dt.date <= end)]
            st.dataframe(filtered[['id', 'customer_name', 'mobile', 'query_type', 'solved_time', 'deo_email']])
            view_id = st.text_input("View Query ID")
            if view_id:
                query = filtered[filtered['id'] == view_id].iloc[0]
                st.write(query)
                if query['attachment']:
                    st.download_button("Download Attachment", query['attachment'])

        elif page == 'Analytics':
            st.subheader("Analytics")
            total_raised = len(all_queries)
            total_solved = len(all_queries[all_queries['status'] == 'solved'])
            st.write(f"Total Raised: {total_raised}")
            st.write(f"Total Solved: {total_solved}")

            if st.button("Query Type Analysis"):
                analysis = all_queries[all_queries['status'] == 'solved'].groupby('query_type').apply(
                    lambda g: ((g['solved_time'] - g['raised_time']).dt.total_seconds() / 60 / len(g)).mean()
                )
                st.write(analysis)

            if role == 'admin':
                if st.button("DEOs"):
                    deos = pd.read_sql("SELECT email, name FROM users WHERE role='deo'", conn)
                    start, end = st.date_input("Date Range", value=(datetime.now().date() - timedelta(days=30), datetime.now().date()))
                    for _, deo in deos.iterrows():
                        if st.button(deo['name']):
                            deo_queries = all_queries[(all_queries['deo_email'] == deo['email']) & (all_queries['raised_time'].dt.date.between(start, end))]
                            st.write(f"Raised: {len(deo_queries)}, Solved: {len(deo_queries[deo_queries['status']=='solved'])}")

            if st.button("RMs"):
                rms = pd.read_sql("SELECT email, name FROM users WHERE role='rm'", conn)
                start, end = st.date_input("Date Range", value=(datetime.now().date() - timedelta(days=30), datetime.now().date()))
                for _, rm in rms.iterrows():
                    if st.button(rm['name']):
                        rm_queries = all_queries[(all_queries['rm_email'] == rm['email']) & (all_queries['raised_time'].dt.date.between(start, end))]
                        st.write(f"Raised: {len(rm_queries)}, Solved: {len(rm_queries[rm_queries['status']=='solved'])}")

            if st.button("Pending"):
                pending = len(all_queries[all_queries['status'] == 'raised'])
                time_est = pending * 5
                hours = time_est // 60
                mins = time_est % 60
                st.write(f"Total Pending: {pending}, Est Time: {hours:02d}:{mins:02d}")

                if role == 'admin':
                    if st.button("DEOs Pending"):
                        deos_pending = all_queries[all_queries['status'] == 'raised'].groupby('deo_email').size()
                        st.write(deos_pending)
                    if st.button("RMs Pending"):
                        rms_pending = all_queries[all_queries['status'] == 'raised'].groupby('rm_email').size()
                        st.write(rms_pending)
                else:
                    if st.button("RMs Pending"):
                        rms_pending = all_queries[all_queries['status'] == 'raised'].groupby('rm_email').size()
                        st.write(rms_pending)

        elif page == 'Team' and role == 'admin':
            st.subheader("Team Management")
            if st.button("DEOs"):
                deos = pd.read_sql("SELECT * FROM users WHERE role='deo'", conn)
                st.dataframe(deos)
                edit_email = st.text_input("Edit DEO Email")
                if edit_email:
                    new_pw = st.text_input("New Password", type='password')
                    status = st.selectbox("Status", ['active', 'deactive', 'pending'])
                    if st.button("Update"):
                        if new_pw:
                            hashed = stauth.Hasher([new_pw]).hash(new_pw)[0]
                            c.execute("UPDATE users SET password=?, status=? WHERE email=?", (hashed, status, edit_email))
                        else:
                            c.execute("UPDATE users SET status=? WHERE email=?", (status, edit_email))
                        conn.commit()
                        st.success("Updated")

            if st.button("RMs"):
                rms = pd.read_sql("SELECT * FROM users WHERE role='rm'", conn)
                st.dataframe(rms)
                edit_email = st.text_input("Edit RM Email")
                if edit_email:
                    new_pw = st.text_input("New Password", type='password')
                    status = st.selectbox("Status", ['active', 'deactive', 'pending'])
                    if st.button("Update"):
                        if new_pw:
                            hashed = stauth.Hasher([new_pw]).hash(new_pw)[0]
                            c.execute("UPDATE users SET password=?, status=? WHERE email=?", (hashed, status, edit_email))
                        else:
                            c.execute("UPDATE users SET status=? WHERE email=?", (status, edit_email))
                        conn.commit()
                        st.success("Updated")