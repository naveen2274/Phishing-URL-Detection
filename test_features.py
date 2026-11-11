
import json
import pandas as pd

from feature_extractor import extract_url_features

# Load the exact feature order expected by the model
with open("models/feature_names.json", "r") as file:
    expected_features = json.load(file)

test_url = "https://www.example.com/login"

features = extract_url_features(test_url)

# Arrange features in the model's expected order
feature_df = pd.DataFrame(
    [[features[name] for name in expected_features]],
    columns=expected_features
)

print("Extracted feature count:", len(features))
print("Model feature count:", len(expected_features))
print("\nExtracted features:")
print(feature_df.T)

print("\nFeature order matches:", 
      list(feature_df.columns) == expected_features)
