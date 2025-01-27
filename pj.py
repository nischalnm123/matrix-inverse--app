import streamlit as st
import numpy as np
import firebase_admin
from firebase_admin import credentials, auth
import pandas as pd
from io import BytesIO


firebase_key={
  "type": "service_account",
  "project_id": "matrix-1d099",
  "private_key_id": "7f92705ac899234cdf493844cab4a13c638242ac",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC946jzRZtr00F4\nUd6/Iu0O+yg4UNvuDgmX44WbFiArKrHtW1qpn/53R6kmDPBr5HpOIRwv/O2frZPZ\ni21FW5n6PD3VERtM/IC/4ZY/QxgQfrWgWDgiV1RaQBHfUPptEt+em8w9xCeVswoX\ni4GIXBBUmDDadQd34Gm4qtE6YGJfkp/pI5YOpdnhXsPzJRyeR+hRpMF0UApWKM9n\nbx1GzcKlnJWkgRStoUO4VTm7g1cQXQ8tfZ1w2vyREDyRq8KiH/H6x9jkRdPdhhJX\nMvto5P+/A69dn1PN4vCJMue2W+i5Yse/kJZDQ9YWK9r33w+sCdWLGhQX6NHP1vPb\n5xolXlUNAgMBAAECggEAIXy0D07PtWi4i4T4oMGCh9lQAvpzhpxQIcqchbiVrLcn\nUKIDL5XJFPT8xfqTLZvJ29xn8aiLqVS9lahKeWhJk8Eq8FfHdkCzXeNlETv+Uu5d\njmzwXVIETLQu0rCfsTuaVwjHsH7WskY0Oem+yrLdqGV8fBIWYpQfYNMy+bYEszDF\nIXRkvHeESCC6VHbSiOmUSvAvoGdgZrLbgx/hov7Zb7wxmMiKlgdK8Y57OpSZQMQw\n+GL7ekX26vh39/Dmm0eQqG75I3kfJdGNxdFAogFoHlwyMwWkhbBIhlfO92R58kj0\ngFy8aHIGiYUp5fBgPbFkSGC5rQxT9fYUlkY31YbqewKBgQDdxhBAOSrHhooPi9oS\nek5pywRMkvwSpObNKeA9YXmyVkuLbgXfkmvEmBzlcJ/9yjHTJ+WQdvesUEi/Sb4v\noGVYxWdNlCPfueT/Jpocvn0eaDmsOFFs6Nxqe60CaVgy17N35fAkQfxyAsv8aEI1\nKnDUpEAw9K6J5RNz/2m4IvJ77wKBgQDbMeS3VKwVm5B7t5KmpeeXp6GEsYF9iGhE\ntp83MTFd913bgoItMngixjb18VbG1OIiQnD98Q0jxuxCinVz/hqCht1QcG7NAycU\nxsNpAnOd9qllGYvMqVt8nTQWpZgWLGY7ed3UEhTKE3KTs8+eHMdJZ3oIC3MNLfov\n4WOnMJ7ywwKBgCnPBBNHc7QnvfFOWS8wlYXGOypAb3sIUWaOJXMM5Edlk1pWxI6w\naNaoIpJymAbdTmVTWSjR9MEsZXqCaXNLFrAUjvQGIHk172DWoykWFDpeRbkc6OTS\nRXNhm20f9PuoxHGvDIWZVwEbW99avFiPhrPfvyY7iof+gptUpFaNaA9LAoGBAIMP\nuCPuWt6on6F5yBQgyvMg5jDDOhvnPgEn+Nc1cMEwsUwZIuEHdlHElwRDg5FrpLK7\na3hLc4Ha5VV8GHJ8kzlMjnQUZgvrQKjpl9nn/12KKQssVSzQbsV58bVA2kkXzyDs\n4zh0fz28lxu9vfxaVMaNOqgowGg2/4s1hzJmngOlAoGAHsRNtn0wUP/inpUilJ9R\ndVnvC5JsFXeKPG/a6C50o+KS8HYGsHXwzz1UJof6kYr1Z8cX6eKmJCheCIek9bJl\nJ0yufvlViUi/YEoLaYPuDzldFpToC53fS5xfULQIMQhrLkkSoZUFTeFvA0JF4xhh\nk6r4SFVhJOKoyfzg4ucjDds=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@matrix-1d099.iam.gserviceaccount.com",
  "client_id": "104852254014677489121",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40matrix-1d099.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}


if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_key)
    firebase_admin.initialize_app(cred)

def register_user(email, password, display_name):
    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=display_name
        )
        return True, f"User {user.display_name} registered successfully!"
    except Exception as e:
        return False, str(e)

def authenticate_user(email, password):
    try:
        user = auth.get_user_by_email(email)
        return True, f"Welcome back, {user.display_name}!"
    except Exception as e:
        return False, "Invalid email or user does not exist."

def calculate_inverse(matrix):
    try:
        matrix_np = np.array(matrix, dtype=float)
        inverse_np = np.linalg.inv(matrix_np)
        return inverse_np, None
    except np.linalg.LinAlgError:
        return None, "Matrix is not invertible!"
    except ValueError:
        return None, "Invalid input! Please enter numeric values."

def generate_report(input_matrix, output_matrix):
    report_data = {
        "Input Matrix": [" ".join(map(str, row)) for row in input_matrix],
        "Output (Inverse Matrix)": [" ".join(map(lambda x: f"{x:.2f}", row)) for row in output_matrix]
    }
    report_df = pd.DataFrame(report_data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        report_df.to_excel(writer, index=False, sheet_name='Matrix Report')
    output.seek(0)
    return output

# Streamlit UI
def main():
    st.set_page_config(page_title="Matrix Inverse Calculator", layout="wide", page_icon="🧮")

    st.title("🧮 Matrix Inverse Calculator")


    if "is_authenticated" not in st.session_state:
        st.session_state.is_authenticated = False
        st.session_state.user_message = ""


    st.sidebar.title("User Authentication")
    if not st.session_state.is_authenticated:
        auth_option = st.sidebar.radio("Choose an option", options=["Login", "Register"])

        if auth_option == "Register":
            st.sidebar.subheader("Register")
            reg_email = st.sidebar.text_input("Email", placeholder="Enter your email")
            reg_password = st.sidebar.text_input("Password", placeholder="Enter your password", type="password")
            reg_display_name = st.sidebar.text_input("Display Name", placeholder="Enter your name")
            if st.sidebar.button("Register"):
                success, message = register_user(reg_email, reg_password, reg_display_name)
                if success:
                    st.sidebar.success(message)
                else:
                    st.sidebar.error(message)

        elif auth_option == "Login":
            st.sidebar.subheader("Login")
            email = st.sidebar.text_input("Email", placeholder="Enter your email")
            password = st.sidebar.text_input("Password", placeholder="Enter your password", type="password")
            if st.sidebar.button("Login"):
                is_authenticated, message = authenticate_user(email, password)
                st.session_state.is_authenticated = is_authenticated
                st.session_state.user_message = message
                if is_authenticated:
                    st.sidebar.success(message)
                else:
                    st.sidebar.error(message)

    if st.session_state.is_authenticated:
        st.sidebar.success(st.session_state.user_message)

        st.header("Matrix Inverse Calculation")

   
        size = st.selectbox("Select Matrix Size", options=[2, 3, 4], index=0)

  
        matrix_key = f"matrix_{size}"  

      
        if matrix_key not in st.session_state:
            st.session_state[matrix_key] = [[0.0] * size for _ in range(size)]

        matrix_input = st.session_state[matrix_key]  

        st.write(f"Enter values for a {size}x{size} matrix:")

        for i in range(size):
            cols = st.columns(size)
            for j in range(size):
                
                matrix_value = matrix_input[i][j]
                
                new_value = cols[j].text_input(
                    f"Row {i+1}, Col {j+1}",
                    value=str(matrix_value),
                    key=f"cell_{size}{i}{j}",
                )
                try:
                    matrix_input[i][j] = float(new_value)
                except ValueError:
                    pass  

       
        if st.button("Calculate Inverse"):
            inverse_matrix, error = calculate_inverse(matrix_input)
            if error:
                st.error(error)
            else:
                col1, col2 = st.columns(2)
                with col1:
                    st.write("Input Matrix:")
                    st.write(np.array(matrix_input))

                with col2:
                    st.write("Inverse Matrix:")
                    st.write(inverse_matrix)

            
                report_file = generate_report(matrix_input, inverse_matrix)
                st.download_button(
                    label="Download Report",
                    data=report_file,
                    file_name="Matrix_Inverse_Report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

if __name__ == "__main__":
    main()
