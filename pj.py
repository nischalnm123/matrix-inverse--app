import streamlit as st
import numpy as np
import firebase_admin
from firebase_admin import credentials, auth
import pandas as pd
from io import BytesIO

# Firebase Admin SDK JSON Key
firebase_key = {
  "type": "service_account",
  "project_id": "intern-7c9f4",
  "private_key_id": "4088b27796536e24091e75f04675e743bed75eed",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbpYlsIGk0c2Vu\nVYXkL+efhL3Qa10sk2dWvaOVCu2KDQ3bLWSRQRmYJSuPLdM9G/Z5dMIla2IWsZry\nCOA60UvTNryO2qr2Tvo4OdmG1Iaf7UY56IUtWD6DIcqEYQLy/JX5ExSwPp3DO0Ta\n7sXfdpCuQohYdMuQyDrtyCZNe4OIQiB2do7uFGJ3pR6EoJTEdGhvvwE+cfa636pK\nJSmdi7EER/UJjBJ8lo19+he5mBjLffBj1qzuHwwV7K/oKFF8CLspMN7e+XcpcgZD\njP9crHGRNFUzwLcwG9a9sbjzZ+W6i9uKnmRwvaeZBByo4KeZQbsQHrJ3HQCUujYa\n9JY2zjsJAgMBAAECggEAAjJ83/sN0SY8jSla6a+SxaniOMIolLut+UerEAG7/GIW\nddIhuc/hSchjNt25k4LEtiPjpmiU1WeDcvLqIMUZ8heIjjxgWSLLSHuUlQvaAgGf\np1X0z1Y6vQTUmY15tQQYz+Uo5Rtf2cTel3fzG3uj1jntN9EfmzcgZyvsp9UHCdIz\ngv8LUeRm0vcbgnUnpQgDqbTLt/LreZBCbLaBj9gtZmFOch5vFTOf6fLwiHZLfCft\naZj/uWDBnz/zfQBvMvhbhMPVcB9emOmZ4AhXfrPIpbMYkwwaFhK+xlx8XvD9hWL8\ntAfrpwEAGYcpcVtI/xHryS1mhNqeuAF+cHjS01okqQKBgQDTUImPbTO97dXzZF3K\ncUgFc8OG1qVnnPX+KVidGh3nGsgsHoW0yhy+S6YhNJyQKkhYzrk2lXSsF1ZrarC3\n3AgjMCT7nLHghss7/BXzA6K06UUSNzTTpn0ypOmM3Jn6TEM7OeOAULITn3CKrKks\nw+kcYH1TL1H2SNRbY6/uBo+h7QKBgQC8j22Ifa4hRxiAs+J30JHiZJbHE+soAIRa\n1H5BzDqTkcWnx6+QBTMrx+HrJ9N40y3fGrJhQipaFvaKsclD6xzSI78Ln8SBwhhY\nSPkXxdhXG/IjK/PwlioNE94PYLk5IJKqpAfbbgjIQ8D1UWEeaEEX8t1c/xKv6rcD\niiNqevbKDQKBgEioWoQsYiweCQClM/KVvNPTGBnW2AymVZbMlKGAB2QdO1KgNA0T\nqYps7HRiaKrRPwr6GYkBHprFc3t/tb+iMlIXDcBOAoNXFa5MYSerylg2FP/MZ6eW\niVnOhldeyrrbWgqVPvoxxOkmW0XzVEAGJLMTIkRl8uKh7BJ4VlebfeuJAoGBAKXd\ngNtsuqzZLkugcNk2Ze2A0EUEV3nTopmHjBxy+x/uPbEN7XhBqrabWDaTzOje0t4L\nTNhS7JBc3Lg6FbIh8jNDcH1YJ/KAewvF/R+VUG2nzoJz2lxKq2jfjhl22tfOuFVU\nfvjdvOn095qT4FtwF7pqT6DLW3PVgvGhJPA4hDhNAoGAEyd7dDr00MHN9ueKsWFa\nZOCMLLrcZE55TeETXSvP4EBtBalvoTMR65ocmY0vStDNpMLp/n6sTjcRAmaXVEMg\nDKdcENMp10n3NrMDQhDSstGNtdyTa0QNPlJ5g4AATrnyblJ/bmvpYmKHnZLevwBe\nMu4OfE8wEMXy9+DTYjP+oYo=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@intern-7c9f4.iam.gserviceaccount.com",
  "client_id": "107171942891220637053",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40intern-7c9f4.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

# Initialize Firebase Admin SDK
# Initialize Firebase Admin SDK (only if not already initialized)
if not firebase_admin._apps:
    cred = credentials.Certificate("./key.json")
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
