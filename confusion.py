import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import sys

# 1. 데이터 로드
df = pd.read_csv("flow_stats_dataset.csv")

# 2. K-Means 수행
feature_cols = [c for c in df.columns if c != 'label']
X = df[feature_cols]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

kmeans = KMeans(n_clusters=84, random_state=42, n_init=10)
df['cluster'] = kmeans.fit_predict(X_scaled)

# 3. 교차표(Confusion Matrix) 생성
# 행: 실제 도메인, 열: 예측된 클러스터 ID
ct = pd.crosstab(df['label'], df['cluster'])

# ==========================================
# [저장 1] 전체 매트릭스를 CSV로 저장 (추천)
# ==========================================
ct.to_csv("confusion_matrix.csv")
print("1. 전체 Confusion Matrix가 'confusion_matrix.csv'로 저장되었습니다.")


# ==========================================
# [저장 2] 분석 리포트를 TXT로 저장
# ==========================================
output_txt_file = "confusion_report.txt"

with open(output_txt_file, "w", encoding="utf-8") as f:
    f.write("=== K-Means Clustering Confusion Analysis Report ===\n\n")
    
    # 상위 혼동 클러스터 분석 로직
    for cluster_id in range(84):
        if cluster_id not in ct.columns: continue
        
        cluster_data = ct[cluster_id]
        if cluster_data.sum() == 0: continue
        
        # 해당 클러스터에 속한 도메인들 중 상위 3개 추출
        top_domains = cluster_data.sort_values(ascending=False).head(3)
        total_in_cluster = cluster_data.sum()
        
        # 1위 도메인의 점유율
        dominance = top_domains.iloc[0] / total_in_cluster
        
        # 90% 미만이면 섞인 것으로 간주하여 기록
        if dominance < 0.9:
            report_str = f"\n[Cluster {cluster_id}] 총 {total_in_cluster}개 플로우 (혼재됨)\n"
            f.write(report_str)
            print(report_str.strip()) # 콘솔에도 출력
            
            for domain, count in top_domains.items():
                if count > 0:
                    detail_str = f"  - {domain}: {count}개 ({count/total_in_cluster*100:.1f}%)\n"
                    f.write(detail_str)
                    print(detail_str.strip())

print(f"2. 분석 리포트가 '{output_txt_file}'로 저장되었습니다.")


# ==========================================
# [저장 3] 히트맵 이미지 저장
# ==========================================
top_20_domains = df['label'].value_counts().head(20).index
subset_ct = ct.loc[top_20_domains]

plt.figure(figsize=(20, 10))
sns.heatmap(subset_ct, cmap="viridis", annot=False)
plt.title("Confusion Heatmap (Top 20 Domains vs Clusters)")
plt.xlabel("Cluster ID")
plt.ylabel("Actual Domain")
plt.tight_layout()

# 화면 출력 전 저장
plt.savefig("confusion_heatmap.png", dpi=300) 
print("3. 히트맵 이미지가 'confusion_heatmap.png'로 저장되었습니다.")

plt.show()