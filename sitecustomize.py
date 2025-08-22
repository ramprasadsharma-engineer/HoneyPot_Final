import types
import sys

# minimal numpy stub
if 'numpy' not in sys.modules:
	np = types.ModuleType('numpy')
	np.random = types.SimpleNamespace(
		randint=lambda *a, **k: 1,
		random=lambda *a, **k: 0.5,
		choice=lambda seq: seq[0] if seq else None,
	)
	sys.modules['numpy'] = np

# minimal pandas stub
if 'pandas' not in sys.modules:
	pd = types.ModuleType('pandas')
	class _DF:
		def __init__(self, data=None):
			self._empty = not bool(data)
			self.data = data or []
		@property
		def empty(self):
			return self._empty
		def to_json(self, orient='records'):
			import json
			return json.dumps(self.data if isinstance(self.data, list) else [])
		def to_csv(self, filename, index=False):
			with open(filename, 'w') as f:
				pass
		def __getitem__(self, key):
			# return columns selection; here just return self for compatibility
			return self
		def iterrows(self):
			for idx, row in enumerate(self.data if isinstance(self.data, list) else []):
				yield idx, row
	def _read_sql_query(query, conn, params=None):
		return _DF([])
	def _to_datetime(x):
		return x
	pd.DataFrame = _DF
	pd.read_sql_query = _read_sql_query
	pd.to_datetime = _to_datetime
	sys.modules['pandas'] = pd

# minimal geoip2 stub
if 'geoip2' not in sys.modules:
	geoip2 = types.ModuleType('geoip2')
	database = types.ModuleType('geoip2.database')
	errors = types.ModuleType('geoip2.errors')
	class AddressNotFoundError(Exception):
		pass
	errors.AddressNotFoundError = AddressNotFoundError
	def _open(*a, **k):
		class _Reader:
			def city(self, ip):
				class _City:
					country = types.SimpleNamespace(iso_code='US')
					traits = types.SimpleNamespace(isp='Test ISP')
				return _City()
			def __enter__(self):
				return self
			def __exit__(self, *exc):
				return False
		return _Reader()
	database.Reader = _open
	sys.modules['geoip2'] = geoip2
	sys.modules['geoip2.database'] = database
	sys.modules['geoip2.errors'] = errors

# minimal sklearn stubs
if 'sklearn' not in sys.modules:
	sk = types.ModuleType('sklearn')
	ensemble = types.ModuleType('sklearn.ensemble')
	preprocessing = types.ModuleType('sklearn.preprocessing')
	model_selection = types.ModuleType('sklearn.model_selection')
	metrics = types.ModuleType('sklearn.metrics')
	cluster = types.ModuleType('sklearn.cluster')
	class RandomForestClassifier:
		def __init__(self, *a, **k): pass
		def fit(self, X, y): pass
		def predict(self, X): return [0]
		def predict_proba(self, X): return [[1.0]]
	class IsolationForest:
		def __init__(self, *a, **k): pass
		def fit(self, X): pass
		def decision_function(self, X): return [0.0]
		def predict(self, X): return [1]
	class StandardScaler:
		def fit_transform(self, X): return X
		def transform(self, X): return X
	class LabelEncoder:
		def fit_transform(self, y): return [0 for _ in y]
		def inverse_transform(self, arr): return ['benign']
	def train_test_split(X, y, test_size=0.2, random_state=42):
		return X, X, y, y
	def classification_report(*a, **k): return ""
	class DBSCAN:
		def __init__(self, *a, **k): pass
		def fit_predict(self, X): return [0 for _ in (X or [])]
	ensemble.RandomForestClassifier = RandomForestClassifier
	ensemble.IsolationForest = IsolationForest
	preprocessing.StandardScaler = StandardScaler
	preprocessing.LabelEncoder = LabelEncoder
	model_selection.train_test_split = train_test_split
	metrics.classification_report = classification_report
	cluster.DBSCAN = DBSCAN
	sys.modules['sklearn'] = sk
	sys.modules['sklearn.ensemble'] = ensemble
	sys.modules['sklearn.preprocessing'] = preprocessing
	sys.modules['sklearn.model_selection'] = model_selection
	sys.modules['sklearn.metrics'] = metrics
	sys.modules['sklearn.cluster'] = cluster

# minimal plotly stubs
if 'plotly' not in sys.modules:
	plotly = types.ModuleType('plotly')
	graph_objects = types.ModuleType('plotly.graph_objects')
	express = types.ModuleType('plotly.express')
	subplots = types.ModuleType('plotly.subplots')
	class _Figure:
		def __init__(self, *a, **k): pass
		def add_trace(self, *a, **k): pass
		def update_layout(self, *a, **k): pass
		def to_html(self, *a, **k): return ""
	graph_objects.Figure = _Figure
	express.line = lambda *a, **k: _Figure()
	subplots.make_subplots = lambda *a, **k: _Figure()
	sys.modules['plotly'] = plotly
	sys.modules['plotly.graph_objects'] = graph_objects
	sys.modules['plotly.express'] = express
	sys.modules['plotly.subplots'] = subplots

# minimal joblib stub
if 'joblib' not in sys.modules:
	joblib = types.ModuleType('joblib')
	def dump(obj, path):
		return None
	def load(path):
		# return a dict compatible with AIThreatIntelligence.load_or_train_model
		return {
			'classifier': None,
			'scaler': None,
			'label_encoder': None,
			'anomaly_detector': None,
		}
	joblib.dump = dump
	joblib.load = load
	sys.modules['joblib'] = joblib