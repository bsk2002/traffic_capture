import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.manifold import TSNE
from sklearn.metrics import adjusted_rand_score
import json

# 1. 데이터 로드 및 시퀀스 변환 (seq_length=512)
with open("../pre-processed_datasets/dataset.json", "r") as f:
    data = json.load(f)

rows = []
SEQ_LENGTH = 512

for label, content in data.items():
    payloads = content.get('payload', {})
    for p_id, p_str in payloads.items():
        # 공백 제거 및 헥사 -> 정수 변환
        clean_hex = p_str.replace(" ", "")
        # 512바이트를 위해 1024개의 헥사 문자 추출
        hex_limited = clean_hex[:SEQ_LENGTH * 2]
        bytes_list = [int(hex_limited[i:i+2], 16) for i in range(0, len(hex_limited), 2)]
        
        # 패딩 (512보다 짧을 경우 0으로 채움)
        if len(bytes_list) < SEQ_LENGTH:
            bytes_list.extend([0] * (SEQ_LENGTH - len(bytes_list)))
            
        rows.append([label] + bytes_list)

feature_cols = [f'byte_{i}' for i in range(SEQ_LENGTH)]
df = pd.DataFrame(rows, columns=['label'] + feature_cols)

# 2. 전처리 (스케일링)
X = df[feature_cols]
print(f"{X}")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 3. K-Means 수행 (k=84)
K = 50
kmeans = KMeans(n_clusters=K, random_state=42, n_init=10)
df['cluster'] = kmeans.fit_predict(X_scaled)

# 4. 평가 (ARI 산출)
ari_score = adjusted_rand_score(df['label'], df['cluster'])
print(f"K={K}, Sequence Length={SEQ_LENGTH} 일 때 ARI: {ari_score:.4f}")

# 5. 시각화 (t-SNE)
# 연산 효율을 위해 5,000개 샘플링
sample_df = df.sample(n=min(5000, len(df)), random_state=42).copy()
sample_X_scaled = scaler.transform(sample_df[feature_cols])

tsne = TSNE(n_components=2, random_state=42, perplexity=30)
X_embedded = tsne.fit_transform(sample_X_scaled)

sample_df['x'] = X_embedded[:, 0]
sample_df['y'] = X_embedded[:, 1]

plt.figure(figsize=(16, 7))

plt.subplot(1, 2, 1)
sns.scatterplot(data=sample_df, x='x', y='y', hue='label', legend=False, palette='tab20', s=10)
plt.title("Ground Truth (By Domain)")

plt.subplot(1, 2, 2)
sns.scatterplot(data=sample_df, x='x', y='y', hue='cluster', legend=False, palette='tab20', s=10)
plt.title(f"K-Means Clustering (K={K}, Seq=512)")

plt.tight_layout()
plt.show()

# 6. 도메인별 클러스터 분포 확인
ct = pd.crosstab(df['label'], df['cluster'])
print(ct.head())