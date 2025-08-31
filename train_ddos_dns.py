# train_dns_ddos.py
import os
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline
from scipy.stats import entropy as shannon_entropy
import joblib
from sklearn.metrics import RocCurveDisplay, PrecisionRecallDisplay

# ---------- Config (Windows-friendly) ----------
DATA_PATH = Path(os.environ.get("DATA_PATH", r"C:\Users\Vaishnavi Gobade\PycharmProjects\CIC-DOS2019\Dataset"))
DATA_FILES = os.environ.get("DATA_FILES", "DrDoS_DNS.csv").split(";")
ARTIFACTS_DIR = Path(os.environ.get("ARTIFACTS_DIR", "."))  # where joblib files are saved
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------- Load ----------
dfs = [pd.read_csv(DATA_PATH / f, low_memory=False) for f in DATA_FILES]
dfs = [df.rename(columns=lambda c: str(c).strip()) for df in dfs]
for i, d in enumerate(dfs):
    print(f"File {i+1} columns: {d.columns.tolist()}")
df = pd.concat(dfs, ignore_index=True)

# ---------- Clean ----------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(axis=1, how='all', inplace=True)
df.dropna(inplace=True)

drop_cols = [
    'Unnamed: 0','Flow ID','Source IP','Destination IP','Timestamp',
    'Fwd Header Length.1','SimillarHTTP','Inbound',
    'Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags',
    'Fwd Avg Bytes/Bulk','Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk','Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate',
    'Init_Win_bytes_forward','Init_Win_bytes_backward',
    'act_data_pkt_fwd','min_seg_size_forward','Source Port',
    'Destination Port','Protocol',
]
df.drop(columns=drop_cols, errors='ignore', inplace=True)

print("\nRemaining columns after drop_cols applied:")
print(df.columns.tolist())

# ---------- Encode label ----------
label_encoder = LabelEncoder()
df['Label'] = label_encoder.fit_transform(df['Label'])
class_names = list(label_encoder.classes_)  # ['BENIGN','DrDoS_DNS']
joblib.dump(label_encoder, ARTIFACTS_DIR / "label_encoder.joblib")
for idx, lab in enumerate(class_names):
    print(f"{idx}: {lab}")

# ---------- Numeric only, split ----------
df = df.select_dtypes(include=[np.number])
X = df.drop('Label', axis=1)
y = df['Label'].astype('int64')
feature_names = X.columns.tolist()
joblib.dump(feature_names, ARTIFACTS_DIR / "features_list.joblib")

# class histogram (original imbalance)
plt.figure(figsize=(10, 7))
df['Label'].map(dict(enumerate(class_names))).value_counts().plot(kind='bar', color='steelblue')
plt.title("Histogram of Attack Type vs Normal Flow (Original)")
plt.xlabel("Attack Type"); plt.ylabel("Count")
plt.grid(axis='y', linestyle='--', alpha=0.6); plt.tight_layout(); plt.show()

print("Whole Data Count:", Counter(y))

X_train, X_test, y_train, y_test = train_test_split(
    X, y, stratify=y, test_size=0.30, random_state=42
)
print("Train Counts (original):", Counter(y_train))
print("Test Counts (original):", Counter(y_test))

# ---------- SMOTE (for reporting plots only) ----------
smote_for_plot = SMOTE(random_state=42, k_neighbors=5, sampling_strategy='auto')
X_train_sm, y_train_sm = smote_for_plot.fit_resample(X_train, y_train)
print("Train Counts after SMOTE (for plot):", Counter(y_train_sm))
plt.figure(figsize=(10, 6)); sns.countplot(x=y_train_sm)
plt.title("Class Distribution After SMOTE (Training Fold)")
plt.xlabel("Encoded Class (0=BENIGN, 1=DrDoS_DNS)"); plt.ylabel("Count"); plt.tight_layout(); plt.show()

def feature_entropy(df_like, bins=20):
    ent = {}
    for col in df_like.columns:
        hist, _ = np.histogram(df_like[col], bins=bins, density=True)
        hist = hist[hist > 0]
        ent[col] = shannon_entropy(hist, base=2)
    return pd.Series(ent, name="entropy").sort_values(ascending=False)

ent_before = feature_entropy(pd.DataFrame(X_train, columns=feature_names))
ent_after  = feature_entropy(pd.DataFrame(X_train_sm, columns=feature_names))
plt.figure(figsize=(14, 5)); ent_before.plot(kind='bar')
plt.title("Feature Entropy (Train, Before SMOTE)"); plt.ylabel("Shannon Entropy (bits)")
plt.tight_layout(); plt.show()
plt.figure(figsize=(14, 5)); ent_after.plot(kind='bar')
plt.title("Feature Entropy (Train, After SMOTE)"); plt.ylabel("Shannon Entropy (bits)")
plt.tight_layout(); plt.show()

def plot_confusion(y_true, y_pred, title):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 7))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names)
    plt.title(title); plt.ylabel('True'); plt.xlabel('Predicted')
    plt.tight_layout(); plt.show()

# ---------- RF pipeline ----------
pipe_rf = Pipeline(steps=[
    ('smote', SMOTE(random_state=42, k_neighbors=5, sampling_strategy='auto')),
    ('rf', RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42))
])
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(pipe_rf, X_train, y_train, cv=cv, scoring='f1_macro', n_jobs=-1)
print(f"RF pipe 5-fold CV f1_macro: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
pipe_rf.fit(X_train, y_train)
y_pred_rf = pipe_rf.predict(X_test)
print("\nRandom Forest (Pipeline) — Test classification report:")
print(classification_report(y_test, y_pred_rf, target_names=class_names))
plot_confusion(y_test, y_pred_rf, "Random Forest (Pipeline) — Confusion Matrix")
y_prob_rf = pipe_rf.predict_proba(X_test)[:, 1]
print("RF ROC-AUC:", roc_auc_score(y_test, y_prob_rf))
print("RF PR-AUC:",  average_precision_score(y_test, y_prob_rf))
RocCurveDisplay.from_estimator(pipe_rf, X_test, y_test); plt.show()
PrecisionRecallDisplay.from_estimator(pipe_rf, X_test, y_test); plt.show()

# feature importances from the fitted RF inside the pipeline
rf_fitted = pipe_rf.named_steps['rf']
rf_importances = rf_fitted.feature_importances_
rf_order = np.argsort(rf_importances)[::-1]

plt.figure(figsize=(12, 12))
plt.title("Feature Importances — Random Forest (Pipeline)")
plt.barh(range(len(feature_names)), rf_importances[rf_order], color='royalblue')
plt.yticks(range(len(feature_names)), [feature_names[i] for i in rf_order])
plt.gca().invert_yaxis()
plt.xlabel("Relative Importance"); plt.grid(axis='x', linestyle='--', alpha=0.6)
plt.tight_layout(); plt.show()

# Histograms for top-k features
k = 20
topk_feats_rf = [feature_names[i] for i in rf_order[:k]]
pd.DataFrame(X, columns=feature_names)[topk_feats_rf].hist(bins=30, figsize=(18, 14), layout=(5, 4))
plt.suptitle(f'Histograms of Top {k} Important Features — RF', fontsize=18, y=1.02)
plt.tight_layout(); plt.show()

# ---------- XGB pipeline ----------
pipe_xgb = Pipeline(steps=[
    ('smote', SMOTE(random_state=42, k_neighbors=5, sampling_strategy='auto')),
    ('xgb', xgb.XGBClassifier(
        eval_metric='logloss', n_estimators=400, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, random_state=42, n_jobs=-1
    ))
])
cv_scores_xgb = cross_val_score(pipe_xgb, X_train, y_train, cv=cv, scoring='f1_macro', n_jobs=-1)
print(f"\nXGB pipe 5-fold CV f1_macro: {cv_scores_xgb.mean():.4f} ± {cv_scores_xgb.std():.4f}")
pipe_xgb.fit(X_train, y_train)
y_pred_xgb = pipe_xgb.predict(X_test)
print("\nXGBoost (Pipeline) — Test classification report:")
print(classification_report(y_test, y_pred_xgb, target_names=class_names))
plot_confusion(y_test, y_pred_xgb, "XGBoost (Pipeline) — Confusion Matrix")
y_prob_xgb = pipe_xgb.predict_proba(X_test)[:, 1]
print("XGB ROC-AUC:", roc_auc_score(y_test, y_prob_xgb))
print("XGB PR-AUC:",  average_precision_score(y_test, y_prob_xgb))
RocCurveDisplay.from_estimator(pipe_xgb, X_test, y_test); plt.show()
PrecisionRecallDisplay.from_estimator(pipe_xgb, X_test, y_test); plt.show()

# XGB importances
xgb_fitted = pipe_xgb.named_steps['xgb']
xgb_importances = xgb_fitted.feature_importances_
xgb_order = np.argsort(xgb_importances)[::-1]

plt.figure(figsize=(12, 12))
plt.title("Feature Importances — XGBoost (Pipeline)")
plt.barh(range(len(feature_names)), xgb_importances[xgb_order], color='royalblue')
plt.yticks(range(len(feature_names)), [feature_names[i] for i in xgb_order])
plt.gca().invert_yaxis()
plt.xlabel("Relative Importance"); plt.grid(axis='x', linestyle='--', alpha=0.6)
plt.tight_layout(); plt.show()

# Histograms for top-k features
topk_feats_xgb = [feature_names[i] for i in xgb_order[:k]]
pd.DataFrame(X, columns=feature_names)[topk_feats_xgb].hist(bins=30, figsize=(18, 14), layout=(5, 4))
plt.suptitle(f'Histograms of Top {k} Important Features — XGBoost', fontsize=18, y=1.02)
plt.tight_layout(); plt.show()

# ---------- Save artifacts ----------
joblib.dump(pipe_rf,  ARTIFACTS_DIR / "rf_pipeline.joblib")
joblib.dump(pipe_xgb, ARTIFACTS_DIR / "xgb_pipeline.joblib")
print(f"Artifacts saved to: {ARTIFACTS_DIR.resolve()}")
