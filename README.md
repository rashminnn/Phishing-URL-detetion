# Phishing URL Detection

A robust machine learning solution designed to identify phishing URLs, featuring a user-friendly web interface and a high-performance backend API. This project provides comprehensive model training, evaluation, and deployment instructions for developers and end-users.

## Table of Contents
- [Overview](#overview)
- [Dataset](#dataset)
- [Model Performance](#model-performance)
- [Installation](#installation)
- [Deployment](#deployment)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [License](#license)
- [Acknowledgements](#acknowledgements)
- [Contributing](#contributing)
- [Contact](#contact)

## Overview
Phishing URLs represent a critical cybersecurity threat, targeting individuals and organizations alike. This project leverages advanced machine learning techniques to classify URLs as either phishing or legitimate. Key components include:
- **Data Preprocessing and Feature Engineering**: Extracts meaningful features from URLs for model training.
- **Model Training and Evaluation**: Compares multiple algorithms, including Decision Tree, Random Forest, XGBoost, and Logistic Regression.
- **Web Application**: Provides a real-time interface for URL analysis, accessible via a deployed web platform or local setup.

## Dataset
The dataset used for training and evaluation is sourced from:
- [Mendeley Data - Phishing URL Dataset](https://data.mendeley.com/datasets/vfszbj9b36/1)

This dataset contains a collection of labeled URLs (phishing and legitimate) used to train and validate the models.

## Model Performance
The project evaluates multiple machine learning models based on accuracy, F1 score, AUC, precision, recall, and training time. The results are summarized below:

| Model               | Accuracy | F1 Score | AUC    | Precision | Recall | Training Time (s) |
|---------------------|----------|----------|--------|-----------|--------|-------------------|
| Decision Tree       | 0.9207   | 0.8693   | 0.9486 | 0.9048    | 0.8366 | 1.0963            |
| Random Forest       | 0.9357   | 0.8962   | 0.9767 | 0.9130    | 0.8799 | 312.8794          |
| XGBoost             | **0.9301**   | **0.8885**   | **0.9739** | **0.8930**    | **0.8840** | **4.1395**            |
| Logistic Regression | 0.8744   | 0.7692   | 0.8748 | 0.7800    | 0.8000 | 111.7700          |

**Recommended Model**: XGBoost  
- **F1 Score**: 0.8885  
- **Model File**: `phishing_model_xgboost.pkl` (located in the project root directory)

The XGBoost model is selected for its balanced performance across metrics and efficient training time, making it ideal for deployment.

## Installation
To set up the project locally, follow these steps:

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm (Node Package Manager)
- Git

### Backend Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/rashminnn/Phishing-URL-detetion.git
   cd Phishing-URL-detetion
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure the `phishing_model_xgboost.pkl` file is in the project root directory.

### Frontend Setup
1. Navigate to the `src` directory and install dependencies:
   ```bash
   cd src
   npm install
   ```
2. Build the frontend:
   ```bash
   npm run build
   ```
3. Serve the production build:
   ```bash
   npm install -g serve
   serve -s build
   ```

## Deployment
### Live Application
The project is deployed and accessible at:  
🔗 [PhishGuard Live](https://phishguard.up.railway.app/)

### Local Deployment
1. **Backend API**:
   - Start the Flask server:
     ```bash
     python app.py
     ```
   - The API will be available at `http://localhost:5000` (or the configured port).
2. **Frontend**:
   - Serve the production build as described in the [Frontend Setup](#frontend-setup) section.
   - Access the web interface at `http://localhost:5000` (or the configured port).

For advanced deployment options, refer to the [Create React App deployment guide](https://cra.link/deployment).

## Project Structure
```plaintext
.
├── app.py                        # Backend API entry point (Flask)
├── phishing_model_xgboost.pkl    # Pre-trained XGBoost model
├── src/                         # React frontend source files
├── build/                       # Production build of frontend
├── data/                        # Dataset storage (not tracked in Git)
├── requirements.txt             # Python dependencies
├── package.json                 # Node.js dependencies and scripts
├── README.md                    # Project documentation
└── LICENSE                      # MIT License file
```

## Usage
1. Place the dataset in the `data/` directory (create the directory if it does not exist).
2. Start the backend server:
   ```bash
   python app.py
   ```
3. Build and serve the frontend as described in the [Frontend Setup](#frontend-setup) section.
4. Open the web interface in a browser to analyze URLs in real-time.

## License
This project is licensed under the [MIT License](LICENSE). See the LICENSE file for details.

## Acknowledgements
- **Dataset**: [Phishing URL Dataset](https://data.mendeley.com/datasets/vfszbj9b36/1)
- **Libraries**: Scikit-learn, XGBoost, Flask, React, and others listed in `requirements.txt` and `package.json`.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please ensure your code follows the project's coding standards and includes appropriate tests.

## Contact
For questions, issues, or suggestions, please:
- Open an issue on the [GitHub repository](https://github.com/rashminnn/Phishing-URL-detetion).
- Contact the maintainer via:
  - **Email**: [rashminpunthila10@gmail.com](mailto:rashminpunthila10@gmail.com)
  - **LinkedIn**: [Rashmin Munasinghe](https://www.linkedin.com/in/rashmin-munasinghe-313b58299/)
