import streamlit as st
import numpy as np
import firebase_admin
from firebase_admin import credentials, auth
import pandas as pd
from io import BytesIO

# Firebase Admin SDK JSON Key
firebase_key = {
  "type": "service_account",
  "project_id": "punk-5c99d",
  "private_key_id": "17871b0098e1f916e5aed10ac0b538ec2f9a2ff6",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOWJcwpAHWv4xI\nyI1hgAvkAzhXy4vYL8kwM0Jyd1cIJinVkfhtXzQJrGOq1boGMVc9LWrIYN/Jy+2G\nnAwowCcBhX+M67oGPburK8SuZclnWQjH8oe0H4/cyUzjSuwl4nHR/W64e8CtLq/Z\ncDjV/4Ih1X3j2d/CGv0WJuUfXFAIzPVIdyv7xQA39mjWpxPHEKD8Kums7McPSRtt\nR7VaunPYTbfDPkaXlhegxqcMtdpN+TxP1A3Mlm7cW9crYRdqwu5BQMM6CwSgpziW\n4xsiAyTcx9gTOZBYLNT18Xe2rroTfOGu6npUclNsQ1QiFGavHoMr/6Y+A0u/iokw\nMGaWepoBAgMBAAECggEACekSGN9VqcZhItlEBhHn8EtxzDCt3qQb5/VcTIJcExt/\nIJ9uRLWA+rJ1hn3VnYjG4XyyD13svaTOW4vY3yesb+ulHsPvFy/lmLDlVUF1AQJT\nFERbHWzzJEXkTBnb+e1UbWMcS17BOCghAMLdrfSDv+OAtH3xO+G/NE5JrJ4Kx4NX\ncvbho6ufnJZ/hYW/NTTuiYm6N6ff87txAuBWH2oY+5YHpr2M+sGFV1/FQEgg8/7c\nGeDaCr5PwcvvkpxoaPhfJ0NbVEzSuIRMTUM1EX/y9GpVbpZjx8cgr0FOcGHLlD+P\nVln95C6WQOxdTzx0336NN3oBpPOpgE6a0X8D/UfLYQKBgQDqm+1efWsyH6QsQgg3\nV2BNVJbJI76KSwgqlaPvEQu3lEKCilVWsNAsYWo303+wi3zBepSnS+Ge8FEs9gcg\nm82LYn655+R3GWqe35vZ2PanmHtFPZA6Xbdey11M06XIzPCYtN475FYboa9LLlCH\n8JBaA7QvELOP7jbImK/UZzp+UQKBgQDhKPfqqrnf+H3SPQZ/uPeK+PBoMrfUrKK4\nwk1+ENBsz4aUAIAfwATPfdrfuHbFlII55BrHAS5Hvpo+zopNuH+WmyvCaF9CYZGW\nABGpT7duSEqX52Vfw99t0a8+xGULA2sLTe86xikNnDCHFrIPUsmYwGqv1nSSAXym\n1QW96BAEsQKBgCTX3+sa3x68AVhB9nBadHEwe42S43VsWxf08A23K5Pk4J0HhGdc\n1RRjJ/8kY8Uh4rGvwnCTZhdDvjvFV1Ezpo/hI+2mESbzAt94Vk1b2UBwncs948yG\nsylb3ocWJc7nAFG69buKHEuylIjF+Tef+8tnEYDiqpBL5KaT8+jzXShBAoGATHkw\nsvhnh0WL3oMxmOHG2eGxLYLEYyx7XAtKbJ3jXIGjsNL2sVHzkFGrrD6nwHWvQWBT\nI/InuOBo3RojaUBXvVxYoX/3ksE2xF6joQDdSUyuYSeLi9ooIdGNFuF3fCUeD0na\nDflN6jx5UviHY6L3q7T2x2AsWYa9wqApghW2kxECgYBtGdWNC66VtxmItw/AqGhj\nVs79VbO+PSG1Cb6lIlmr/5kaZAnJYyJigADlO9Q0Mr59gF5V7iBTX0jTfuWuDnn9\nXCIEYidjLxxKDwZJHKDXeJGaXZJz2Ngwx67xIWK5G+1g8yUQuWtfvk794P1YSFWd\ndIDolqA+cO/Dqo/Trnzz6Q==\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@punk-5c99d.iam.gserviceaccount.com",
  "client_id": "116628164597619278711",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40punk-5c99d.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}


# Initialize Firebase Admin SDK
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
    output.seek(0)  # Reset the pointer to the beginning of the file
    return output

# Streamlit UI
def main():
    st.set_page_config(page_title="Matrix Inverse Calculator", layout="wide", page_icon="🧮")

    st.title("🧮 Matrix Inverse Calculator")

    # Session-based authentication state
    if "is_authenticated" not in st.session_state:
        st.session_state.is_authenticated = False
        st.session_state.user_message = ""

    # Login/Registration Section
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

        # Main Functionality after Login
        st.header("Matrix Inverse Calculation")

        # Step 1: Matrix Size Input
        size = st.selectbox("Select Matrix Size", options=[2, 3, 4], index=0)

        # Step 2: Matrix Input with Persistent State
        matrix_key = f"matrix_{size}"  # Unique key for the matrix size

        # Initialize matrix in session state if not already
        if matrix_key not in st.session_state:
            st.session_state[matrix_key] = [[0.0] * size for _ in range(size)]

        matrix_input = st.session_state[matrix_key]  # Reference session state matrix

        st.write(f"Enter values for a {size}x{size} matrix:")

        for i in range(size):
            cols = st.columns(size)
            for j in range(size):
                # Display existing value from session state
                matrix_value = matrix_input[i][j]
                # Update session state when the user changes a value
                new_value = cols[j].text_input(
                    f"Row {i+1}, Col {j+1}",
                    value=str(matrix_value),
                    key=f"cell_{size}{i}{j}",
                )
                try:
                    matrix_input[i][j] = float(new_value)
                except ValueError:
                    pass  # Ignore invalid inputs temporarily

        # Submit Button
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

                # Generate Report
                report_file = generate_report(matrix_input, inverse_matrix)
                st.download_button(
                    label="Download Report",
                    data=report_file,
                    file_name="Matrix_Inverse_Report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

if __name__ == "__main__":
    main()
