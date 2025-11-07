"""
ML Model Training Pipeline for URL Attack Detection
Trains ensemble models: Random Forest, XGBoost, and Neural Network
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import os
import sys

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("Warning: XGBoost not available")

try:
    from sklearn.neural_network import MLPClassifier
    NN_AVAILABLE = True
except ImportError:
    NN_AVAILABLE = False
    print("Warning: Neural Network not available")


class URLFeatureExtractor:
    """Extract features from URLs for ML training"""

    @staticmethod
    def extract_statistical_features(url: str) -> dict:
        """Extract statistical features from URL"""
        features = {
            'length': len(url),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special': sum(not c.isalnum() for c in url),
            'num_slashes': url.count('/'),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_percent': url.count('%'),
            'num_questions': url.count('?'),
            'num_ampersands': url.count('&'),
            'num_equals': url.count('='),
            'entropy': URLFeatureExtractor._calculate_entropy(url),
        }
        return features

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0

        entropy = 0
        for char in set(text):
            prob = text.count(char) / len(text)
            if prob > 0:
                entropy -= prob * np.log2(prob)

        return entropy


class AttackDetectionTrainer:
    """Train ML models for attack detection"""

    def __init__(self, dataset_path: str):
        """
        Initialize trainer.

        Args:
            dataset_path: Path to CSV dataset
        """
        self.dataset_path = dataset_path
        self.df = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.vectorizer = None
        self.label_encoder = None
        self.models = {}

    def load_data(self):
        """Load dataset from CSV"""
        print(f"Loading dataset from {self.dataset_path}...")
        self.df = pd.read_csv(self.dataset_path)

        print(f"Dataset loaded: {len(self.df)} samples")
        print(f"Columns: {self.df.columns.tolist()}")
        print(f"\nLabel distribution:\n{self.df['label'].value_counts()}")
        print(f"\nAttack type distribution:\n{self.df['attack_type'].value_counts()}")

        return self.df

    def preprocess_data(self, test_size: float = 0.2):
        """
        Preprocess data for training.

        Args:
            test_size: Fraction of data for testing
        """
        print("\nPreprocessing data...")

        # Extract URLs and labels
        X = self.df['url'].values
        y = self.df['attack_type'].values

        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        print(f"Classes: {self.label_encoder.classes_}")

        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
        )

        print(f"Training samples: {len(self.X_train)}")
        print(f"Testing samples: {len(self.X_test)}")

        # Vectorize URLs using TF-IDF
        print("\nVectorizing URLs...")
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            analyzer='char',
            lowercase=True,
        )

        self.X_train = self.vectorizer.fit_transform(self.X_train)
        self.X_test = self.vectorizer.transform(self.X_test)

        print(f"Feature matrix shape: {self.X_train.shape}")

    def train_random_forest(self):
        """Train Random Forest classifier"""
        print("\n" + "="*60)
        print("Training Random Forest Classifier...")
        print("="*60)

        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )

        rf_model.fit(self.X_train, self.y_train)

        # Evaluate
        y_pred = rf_model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)

        print(f"\nRandom Forest Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(
            self.y_test, y_pred,
            target_names=self.label_encoder.classes_
        ))

        self.models['random_forest'] = rf_model

        return rf_model

    def train_xgboost(self):
        """Train XGBoost classifier"""
        if not XGBOOST_AVAILABLE:
            print("XGBoost not available, skipping...")
            return None

        print("\n" + "="*60)
        print("Training XGBoost Classifier...")
        print("="*60)

        xgb_model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            verbosity=1
        )

        xgb_model.fit(self.X_train, self.y_train)

        # Evaluate
        y_pred = xgb_model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)

        print(f"\nXGBoost Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(
            self.y_test, y_pred,
            target_names=self.label_encoder.classes_
        ))

        self.models['xgboost'] = xgb_model

        return xgb_model

    def train_neural_network(self):
        """Train Neural Network classifier"""
        if not NN_AVAILABLE:
            print("Neural Network not available, skipping...")
            return None

        print("\n" + "="*60)
        print("Training Neural Network...")
        print("="*60)

        nn_model = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size=128,
            learning_rate='adaptive',
            learning_rate_init=0.001,
            max_iter=100,
            random_state=42,
            verbose=True
        )

        nn_model.fit(self.X_train, self.y_train)

        # Evaluate
        y_pred = nn_model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)

        print(f"\nNeural Network Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(
            self.y_test, y_pred,
            target_names=self.label_encoder.classes_
        ))

        self.models['neural_network'] = nn_model

        return nn_model

    def train_ensemble(self):
        """Train ensemble voting classifier"""
        print("\n" + "="*60)
        print("Training Ensemble Model...")
        print("="*60)

        estimators = []

        if 'random_forest' in self.models:
            estimators.append(('rf', self.models['random_forest']))

        if 'xgboost' in self.models:
            estimators.append(('xgb', self.models['xgboost']))

        if 'neural_network' in self.models:
            estimators.append(('nn', self.models['neural_network']))

        if len(estimators) < 2:
            print("Need at least 2 models for ensemble, skipping...")
            return None

        ensemble_model = VotingClassifier(
            estimators=estimators,
            voting='soft',
            n_jobs=-1
        )

        ensemble_model.fit(self.X_train, self.y_train)

        # Evaluate
        y_pred = ensemble_model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)

        print(f"\nEnsemble Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(
            self.y_test, y_pred,
            target_names=self.label_encoder.classes_
        ))

        self.models['ensemble'] = ensemble_model

        return ensemble_model

    def save_models(self, output_dir: str):
        """
        Save trained models and preprocessing components.

        Args:
            output_dir: Directory to save models
        """
        os.makedirs(output_dir, exist_ok=True)

        # Save best model (Random Forest by default)
        best_model = self.models.get('random_forest') or list(self.models.values())[0]

        model_data = {
            'model': best_model,
            'vectorizer': self.vectorizer,
            'label_encoder': self.label_encoder,
            'feature_names': self.vectorizer.get_feature_names_out() if hasattr(self.vectorizer, 'get_feature_names_out') else None,
        }

        model_path = os.path.join(output_dir, 'attack_detection_model.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"\nModel saved to: {model_path}")

        # Save all individual models
        for model_name, model in self.models.items():
            model_path = os.path.join(output_dir, f'{model_name}_model.pkl')
            model_data = {
                'model': model,
                'vectorizer': self.vectorizer,
                'label_encoder': self.label_encoder,
            }
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)

            print(f"Saved {model_name} to: {model_path}")

    def generate_report(self, output_dir: str):
        """Generate training report"""
        report_path = os.path.join(output_dir, 'training_report.txt')

        with open(report_path, 'w') as f:
            f.write("URL Attack Detection - ML Training Report\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Dataset: {self.dataset_path}\n")
            f.write(f"Total samples: {len(self.df)}\n")
            f.write(f"Training samples: {len(self.X_train)}\n")
            f.write(f"Testing samples: {len(self.X_test)}\n\n")

            f.write("Label Distribution:\n")
            f.write(str(self.df['label'].value_counts()) + "\n\n")

            f.write("Attack Type Distribution:\n")
            f.write(str(self.df['attack_type'].value_counts()) + "\n\n")

            f.write("Trained Models:\n")
            for model_name in self.models.keys():
                f.write(f"  - {model_name}\n")

            f.write("\nModel Accuracies:\n")
            for model_name, model in self.models.items():
                y_pred = model.predict(self.X_test)
                accuracy = accuracy_score(self.y_test, y_pred)
                f.write(f"  {model_name}: {accuracy:.4f}\n")

        print(f"\nTraining report saved to: {report_path}")


def main():
    """Main training pipeline"""
    print("URL Attack Detection - ML Training Pipeline")
    print("=" * 60)

    # Paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, "..", "data", "datasets", "url_attacks_dataset.csv")
    model_dir = os.path.join(script_dir, "..", "data", "models")

    # Check if dataset exists
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        print("Please run generate_dataset.py first!")
        return

    # Initialize trainer
    trainer = AttackDetectionTrainer(dataset_path)

    # Load and preprocess data
    trainer.load_data()
    trainer.preprocess_data(test_size=0.2)

    # Train models
    trainer.train_random_forest()

    if XGBOOST_AVAILABLE:
        trainer.train_xgboost()

    if NN_AVAILABLE:
        trainer.train_neural_network()

    # Train ensemble
    if len(trainer.models) >= 2:
        trainer.train_ensemble()

    # Save models
    trainer.save_models(model_dir)

    # Generate report
    trainer.generate_report(model_dir)

    print("\n" + "=" * 60)
    print("Training completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
