import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Chargement des données
df = pd.read_csv('network_data.csv')

# Traitement préliminaire
# Convertir les données catégorielles en données numériques, par exemple
df['protocol'] = df['protocol'].astype('category').cat.codes
df['tcp_flags'] = df['tcp_flags'].fillna('None').astype('category').cat.codes
df.fillna(0, inplace=True)  # Remplacer les NaN par 0 ou une autre valeur selon le cas

# Normalisation des caractéristiques numériques
scaler = StandardScaler()
scaled_features = scaler.fit_transform(df[['length', 'src_port', 'dst_port', 'icmp_type', 'tcp_flags']])

# Entraînement de l'Isolation Forest
clf = IsolationForest(n_estimators=100, contamination='auto')
clf.fit(scaled_features)

# Prédiction des anomalies
predictions = clf.predict(scaled_features)
df['anomaly'] = predictions

# Identifier les anomalies (les anomalies sont marquées comme -1)
anomalies = df[df['anomaly'] == -1]
