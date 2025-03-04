# 🛡️ CYBERSHIELDx API

🚀 **CYBERSHIELDx API** is a powerful Fast API-based system providing essential security services such as phishing detection, virus scanning, steganography analysis, internet speed testing, and more. Designed for scalability and security, it integrates authentication, logging, and admin controls for robust security management.

## 📌 Features

✅ **User Authentication** – Secure login & token-based authentication using Fast API.

&#x20;✅ **Admin Panel** – User management, logging, and rate limiting.

✅ **Security Tools** – Phishing detection, virus scanning, steganography analysis.

✅ **Internet Speed Test** – Integrated Speed-test API for real-time speed monitoring.

&#x20;✅ **CORS & Middle ware** – Secure API with CORS and authentication middleware. ✅ **Logging & Monitoring** – Logs all API requests and admin activities.

## 🛠️ Tech Stack

- **Backend**: FastAPI, SQLAlchemy
- **Database**: PostgreSQL / MySQL
- **Security**: OAuth2, JWT, Rate Limiting
- **Infrastructure**: Docker, Kubernetes, Terraform

## 🚀 Installation

### 1️⃣ Clone Repository

```sh
https://github.com/lnvpatel/CYBERSHIELDx.git
cd CYBERSHIELDx
```

### 2️⃣ Install Dependencies

```sh
pip install -r requirements.txt
```

### 3️⃣ Set Up Environment Variables

Create a `.env` file and configure your settings:

```
# General App Settings
APP_NAME = CYBERSHIELDx API
VERSION = 1.0.1

#SMTP Configuration
EMAIL_HOST = smtp.gmail.com
EMAIL_PORT = 587
EMAIL_FROM = example@gmail.com
EMAIL_USERNAME = example@gmail.com
EMAIL_PASSWORD = ocjrucjhjfhn
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False

#Security Configuration
SECRET_KEY = 170b5fa78ea6158c32ba084f2345b8ff7a23ff0dabc3cae672b6f90exjkbkjxaxajknkjwsxac87748c
ALGORITHM = HS256
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database Configuration
DATABASE_URL = databse url

```

### 4️⃣ Run the Application

```sh
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## 🐳 Docker Deployment

### Build & Run Container

```sh
docker build -t backend-security-api .
docker run -p 8000:8000 backend-security-api
```

## ☁️ Kubernetes Deployment

Apply the deployment configuration:

```sh
kubectl apply -f k8s/deployment.yaml
```

## 🌎 Deploy to Multi-Cloud with Terraform

```sh
terraform init
terraform apply
```

## 📌 API Endpoints

| Endpoint         | Method | Description                       |
| ---------------- | ------ | --------------------------------- |
| `/auth/login`    | POST   | User login                        |
| `/auth/signup`   | POST   | User registration                 |
| `/speedtest`     | GET    | Internet speed test               |
| `/virus-scan`    | POST   | Scan files for viruses            |
| `/steganography` | POST   | Analyze hidden messages in images |
| `/phising`       | POST   | Phising URL Detection             |
| `/image/`        | POST   | Image Resizer and Compression     |
| `/ip-detection`  | GET    | Suspicious/Proxy Ip Detection     |

and vice versa


## 📜 License

This project is licensed under the MIT License.

---

**🚀 Developed with FastAPI & ❤️ by [Vatsalya Patel]**

