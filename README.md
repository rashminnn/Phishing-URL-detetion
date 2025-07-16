# Phishing URL Detection

A machine learning solution for detecting phishing URLs, featuring a web interface and backend API. The project includes model comparison, deployment instructions, and usage guidelines for both developers and end-users.

## Dataset

- **Source:** [Mendeley Data - Phishing URL Dataset](https://data.mendeley.com/datasets/vfszbj9b36/1)

## Project Overview

Phishing URLs pose significant threats to users and organizations. This project uses machine learning models to classify URLs as phishing or legitimate. The workflow includes:

- Data preprocessing and feature engineering
- Model training and evaluation (Decision Tree, Random Forest, XGBoost, Logistic Regression)
- Web application for real-time URL analysis

## Model Comparison

| Model               | Accuracy |   F1   |   AUC   | Precision | Recall  |    Time    |
|---------------------|----------|--------|---------|-----------|---------|------------|
| Decision Tree       | 0.9207   | 0.8693 | 0.9486  | 0.9048    | 0.8366  |   1.0963   |
| Random Forest       | 0.9357   | 0.8962 | 0.9767  | 0.9130    | 0.8799  | 312.8794   |
| XGBoost             | 0.9301   | 0.8885 | 0.9739  | 0.8930    | 0.8840  |   4.1395   |
| Logistic Regression | 0.8119   | 0.7244 |   N/A   |   0.78    |  0.80   |    N/A     |

**Recommended Model:** XGBoost  
- **F1 Score:** 0.8885  
- **Model Saved As:** `phishing_model_xgboost.pkl` (located in the same directory as `app.py`)

## Deployment

### Web Application

The project is deployed and available at:  
🔗 [PhishGuard Live](https://phishguard.up.railway.app/)

### Local Development

#### Backend (Python API)

- Main entry point: `app.py`
- Run locally:
  ```bash
  python app.py
  ```

#### Frontend (React)

- Build the frontend:
  ```bash
  npm run build
  ```
- Serve the production build:
  ```bash
  npm install -g serve
  serve -s build
  ```
- Access the application at [http://localhost:5000](http://localhost:5000) (or your configured port).

For more deployment guidance, see [Create React App deployment](https://cra.link/deployment).

## Project Structure

```
.
├── app.py
├── phishing_model_xgboost.pkl
├── src/                 # Frontend source files (React)
├── build/               # Production build of frontend
├── requirements.txt
├── package.json
└── README.md
```

## Usage

1. Place the dataset in the appropriate directory (`data/`).
2. Train the model and start the backend server:
   ```bash
   python app.py
   ```
3. Build and serve the frontend as shown above.
4. Access the web interface to analyze URLs.


## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Dataset: [Phishing URL Dataset](https://data.mendeley.com/datasets/vfszbj9b36/1)

---

**For questions or contributions, please open an issue or pull request.**
