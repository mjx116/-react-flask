from flask import Flask, request, jsonify, g
from flask_cors import CORS
import pandas as pd
import numpy as np
import time
import sqlite3
import hashlib
import jwt  # 确保已安装PyJWT库
import datetime
from functools import wraps
import os
from contextlib import contextmanager

# ========== 初始化 Flask 应用 ==========
app = Flask(__name__)
# 配置 CORS：允许所有来源（开发环境），支持所有/api/*路径
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secure-secret-key-here')  # 用于JWT加密
app.config['DATABASE'] = 'users.db'  # SQLite数据库文件
app.config['TOKEN_EXPIRATION'] = 24 * 60 * 60  # Token有效期：24小时


# ========== 数据库相关函数 ==========
def get_db():
    """获取数据库连接"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row  # 使查询结果可以通过列名访问
    return db


@app.teardown_appcontext
def close_connection(exception):
    """关闭数据库连接"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库表结构"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 创建用户表
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           username
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           email
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           password_hash
                           TEXT
                           NOT
                           NULL,
                           created_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           last_login
                           TIMESTAMP
                       )
                       ''')
        db.commit()


# 初始化数据库
init_db()


# ========== 数据库操作上下文管理器 ==========
@contextmanager
def db_operation():
    """数据库操作上下文管理器，自动处理提交和回滚"""
    db = get_db()
    cursor = db.cursor()
    try:
        yield cursor
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        cursor.close()


# ========== 认证相关工具函数 ==========
def hash_password(password):
    """密码加密函数"""
    # 使用SHA-256加盐哈希
    salt = os.urandom(16)
    hash_obj = hashlib.sha256(salt + password.encode('utf-8'))
    return salt.hex() + ':' + hash_obj.hexdigest()


def verify_password(stored_hash, password):
    """验证密码函数"""
    if not stored_hash or ':' not in stored_hash:
        return False
    salt_hex, hash_hex = stored_hash.split(':', 1)
    salt = bytes.fromhex(salt_hex)
    hash_obj = hashlib.sha256(salt + password.encode('utf-8'))
    return hash_obj.hexdigest() == hash_hex


def generate_token(user_id, username):
    """生成JWT令牌"""
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config['TOKEN_EXPIRATION'])
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': expiration
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token, expiration


def token_required(f):
    """需要认证的路由装饰器，优化请求头解析"""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[len('Bearer '):].strip()
        elif auth_header and not auth_header.lower().startswith('bearer '):
            token = auth_header.strip()

        if not token or token.lower() == 'null':
            return jsonify({
                'code': 401,
                'msg': '认证失败：未提供有效的令牌',
                'data': None
            }), 401, {'WWW-Authenticate': 'Bearer'}

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = payload['user_id']
            current_username = payload['username']

            with db_operation() as cursor:
                cursor.execute('SELECT id, username, email FROM users WHERE id = ?', (current_user_id,))
                user = cursor.fetchone()

                if not user:
                    return jsonify({
                        'code': 401,
                        'msg': '认证失败：用户不存在',
                        'data': None
                    }), 401

                kwargs['current_user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email']
                }

        except jwt.ExpiredSignatureError:
            return jsonify({
                'code': 401,
                'msg': '认证失败：令牌已过期',
                'data': None
            }), 401, {'X-Token-Expired': 'true'}

        except jwt.InvalidTokenError:
            return jsonify({
                'code': 401,
                'msg': '认证失败：无效的令牌',
                'data': None
            }), 401

        except Exception as e:
            print(f"Token验证错误: {str(e)}")
            return jsonify({
                'code': 500,
                'msg': '认证过程异常，请联系管理员',
                'data': None
            }), 500

        return f(*args, **kwargs)

    return decorated


# ========== 工具函数：添加重试机制 ==========
def retry(max_retries=2, delay=0.5):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    print(f"【重试机制】第 {i + 1} 次重试，错误：{str(e)[:50]}")
                    if i == max_retries - 1:
                        return generate_base_sim_data(*args, **kwargs)
                    time.sleep(delay)

        return wrapper

    return decorator


# ========== 工具函数：生成基础模拟数据 ==========
def generate_base_sim_data(start_date, end_date, freq='M'):
    """生成标准化模拟数据，确保日期和数值格式正确"""
    try:
        try:
            dates = pd.date_range(start=start_date, end=end_date, freq=freq)
            if len(dates) == 0:
                raise ValueError("无效日期范围")
        except:
            dates = pd.date_range(start='2020-01-01', end='2020-12-31', freq=freq)

        dates_str = dates.strftime('%Y-%m-%d').tolist()
        base_price = 1.0 if freq == 'M' else 3000.0

        prices = []
        current = base_price
        for date in dates_str:
            volatility = np.random.uniform(-0.02, 0.03)
            current = max(current * (1 + volatility), 0.5)
            prices.append({
                'date': date,
                'close': float(round(current, 4))
            })

        return prices
    except Exception as e:
        print(f"生成基础数据失败: {str(e)}")
        fixed_dates = [f'2020-{m:02d}-01' for m in range(1, 13)]
        return [{'date': d, 'close': float(1.0 + (i * 0.05))} for i, d in enumerate(fixed_dates)]


# ========== 认证接口 ==========
@app.route('/api/register', methods=['POST'])
def register():
    """用户注册接口，优化响应头"""
    try:
        data = request.json or {}

        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'code': 1,
                    'msg': f'注册失败：{field}不能为空',
                    'data': None
                }), 400

        username = data['username'].strip()
        email = data['email'].strip()
        password = data['password']

        if len(username) < 3 or len(username) > 20:
            return jsonify({
                'code': 1,
                'msg': '注册失败：用户名长度必须在3-20个字符之间',
                'data': None
            }), 400

        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify({
                'code': 1,
                'msg': '注册失败：请输入有效的邮箱地址',
                'data': None
            }), 400

        if len(password) < 6:
            return jsonify({
                'code': 1,
                'msg': '注册失败：密码长度必须至少6个字符',
                'data': None
            }), 400

        with db_operation() as cursor:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                return jsonify({
                    'code': 1,
                    'msg': '注册失败：用户名已存在',
                    'data': None
                }), 400

            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return jsonify({
                    'code': 1,
                    'msg': '注册失败：邮箱已被注册',
                    'data': None
                }), 400

            password_hash = hash_password(password)
            cursor.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )

            user_id = cursor.lastrowid
            token, expiration = generate_token(user_id, username)

            response = jsonify({
                'code': 0,
                'msg': '注册成功',
                'data': {
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'token': token,
                    'expires_at': expiration.timestamp()
                }
            })
            response.headers['X-Token-Expires-At'] = str(int(expiration.timestamp()))
            return response

    except Exception as e:
        error_msg = f'注册失败: {str(e)[:100]}'
        print(f"【注册错误】{error_msg}")
        return jsonify({
            'code': 1,
            'msg': error_msg,
            'data': None
        }), 500


@app.route('/api/login', methods=['POST'])
def login():
    """用户登录接口，优化响应头"""
    try:
        data = request.json or {}

        if 'username' not in data or not data['username']:
            return jsonify({
                'code': 1,
                'msg': '登录失败：用户名为空',
                'data': None
            }), 400

        if 'password' not in data or not data['password']:
            return jsonify({
                'code': 1,
                'msg': '登录失败：密码为空',
                'data': None
            }), 400

        username = data['username'].strip()
        password = data['password']

        with db_operation() as cursor:
            cursor.execute('SELECT id, username, email, password_hash FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if not user:
                return jsonify({
                    'code': 1,
                    'msg': '登录失败：用户名或密码错误',
                    'data': None
                }), 401

            if not verify_password(user['password_hash'], password):
                return jsonify({
                    'code': 1,
                    'msg': '登录失败：用户名或密码错误',
                    'data': None
                }), 401

            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (current_time, user['id'])
            )

            token, expiration = generate_token(user['id'], user['username'])

            # 添加自定义响应头
            response = jsonify({
                'code': 0,
                'msg': '登录成功',
                'data': {
                    'user_id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'token': token,
                    'expires_at': expiration.timestamp(),
                    'last_login': current_time
                }
            })
            response.headers['X-Token-Expires-At'] = str(int(expiration.timestamp()))
            return response

    except Exception as e:
        error_msg = f'登录失败: {str(e)[:100]}'
        print(f"【登录错误】{error_msg}")
        return jsonify({
            'code': 1,
            'msg': error_msg,
            'data': None
        }), 500


@app.route('/api/logout', methods=['POST'])
@token_required
def logout(**kwargs):
    """用户登出接口"""
    response = jsonify({
        'code': 0,
        'msg': '登出成功',
        'data': None
    })
    # 添加清除令牌的提示头
    response.headers['X-Clear-Token'] = 'true'
    return response


@app.route('/api/user/info', methods=['GET'])
@token_required
def get_user_info(**kwargs):
    """获取当前用户信息接口"""
    current_user = kwargs.get('current_user')

    if not current_user:
        return jsonify({
            'code': 1,
            'msg': '获取用户信息失败',
            'data': None
        }), 401

    return jsonify({
        'code': 0,
        'msg': '获取用户信息成功',
        'data': current_user
    })


# ========== 业务接口 ==========
@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查接口，用于前端确认服务状态"""
    try:
        response = jsonify({
            'code': 0,
            'msg': '后端服务正常运行',
            'data': {
                'timestamp': int(time.time()),
                'service': 'stock-portfolio-api',
                'status': 'running'
            }
        })
        # 添加缓存控制头，防止健康检查结果被缓存
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return response
    except Exception as e:
        return jsonify({
            'code': 1,
            'msg': f'健康检查失败: {str(e)[:50]}',
            'data': {'status': 'error'}
        }), 500


@app.route('/api/index_kline', methods=['POST'])
@token_required
@retry(max_retries=2)
def index_kline(**kwargs):
    try:
        params = request.json or {}
        start_date = str(params.get('start_date', '2020-01-01'))
        end_date = str(params.get('end_date', '2020-12-31'))

        indices = {
            '上证综指': 'sh.000001',
            '深证成指': 'sz.399001',
            '中证500': 'sh.000905',
            '沪深300': 'sh.000300'
        }

        result = {}
        for name in indices.keys():
            result[name] = generate_base_sim_data(start_date, end_date, freq='D')

        # 添加数据时效性头
        response = jsonify({
            'code': 0,
            'data': result,
            'msg': '指数数据获取成功（模拟数据）'
        })
        response.headers['X-Data-Source'] = 'simulation'
        return response

    except Exception as e:
        error_msg = f'指数数据获取失败: {str(e)[:100]}'
        print(f"【接口错误】{error_msg}")
        return jsonify({
            'code': 1,
            'msg': error_msg,
            'data': {name: [] for name in ['上证综指', '深证成指', '中证500', '沪深300']}
        })


@app.route('/api/portfolio_analysis', methods=['POST'])
@token_required
@retry(max_retries=2)
def portfolio_analysis(**kwargs):
    try:
        # 基础配置
        stocks = ['上海机场', '宝钢股份', '中国石化', '中国联通', '中国石油']
        params = request.json or {}
        start_date = str(params.get('start_date', '2018-01-01'))
        end_date = str(params.get('end_date', '2018-12-31'))

        # 1. 生成股票归一化数据
        normalized_data = {}
        for stock in stocks:
            normalized_data[stock] = generate_base_sim_data(start_date, end_date, freq='M')

        # 2. 生成相关系数矩阵
        corr_matrix = {}
        for i, stock1 in enumerate(stocks):
            corr_matrix[stock1] = {}
            for j, stock2 in enumerate(stocks):
                if i == j:
                    corr = 1.0
                else:
                    # 同行业股票相关性更高
                    if (stock1 in ['中国石化', '中国石油']) and (stock2 in ['中国石化', '中国石油']):
                        corr = float(round(np.random.uniform(0.6, 0.8), 2))
                    else:
                        corr = float(round(np.random.uniform(-0.2, 0.4), 2))
                corr_matrix[stock1][stock2] = corr

        # 3. 生成可行集与有效前沿
        feasible_set = []
        for _ in range(120):
            vp = float(round(np.random.uniform(0.08, 0.45), 4))  # 波动率
            rp = float(round(0.05 + (vp - 0.08) * 0.3 + np.random.uniform(-0.015, 0.015), 4))  # 收益率
            rp = max(rp, 0.02)  # 最低收益
            feasible_set.append({'vp': vp, 'rp': rp})

        # 有效前沿（按风险排序取最高收益）
        feasible_set_sorted = sorted(feasible_set, key=lambda x: x['vp'])
        efficient_frontier = []
        max_rp = 0.0
        for p in feasible_set_sorted:
            if p['rp'] > max_rp:
                max_rp = p['rp']
                efficient_frontier.append(p)

        # 4. 关键组合计算
        min_vol_portfolio = min(feasible_set, key=lambda x: x['vp'])  # 最小方差组合
        risk_free_rate = 0.03  # 无风险利率

        # 市场组合（夏普比率最高）
        def sharpe_ratio(p):
            return (p['rp'] - risk_free_rate) / p['vp'] if p['vp'] > 0 else 0.0

        market_portfolio = max(feasible_set, key=sharpe_ratio)

        # 返回结果
        response = jsonify({
            'code': 0,
            'data': {
                'normalized_data': normalized_data,
                'corr_matrix': corr_matrix,
                'feasible_set': feasible_set,
                'efficient_frontier': efficient_frontier,
                'min_vol_portfolio': {
                    'vp': float(min_vol_portfolio['vp']),
                    'rp': float(min_vol_portfolio['rp'])
                },
                'market_portfolio': {
                    'vp': float(market_portfolio['vp']),
                    'rp': float(market_portfolio['rp'])
                },
                'risk_free_rate': float(risk_free_rate),
                'stock_names': stocks
            },
            'msg': '投资组合数据获取成功（模拟数据）'
        })
        response.headers['X-Data-Source'] = 'simulation'
        return response

    except Exception as e:
        error_msg = f'投资组合数据获取失败: {str(e)[:100]}'
        print(f"【接口错误】{error_msg}")
        # 异常时返回完整空结构
        stocks = ['上海机场', '宝钢股份', '中国石化', '中国联通', '中国石油']
        stock_default = {stock: [] for stock in stocks}
        corr_default = {stock: {s: 0.0 for s in stocks} for stock in stocks}
        return jsonify({
            'code': 1,
            'msg': error_msg,
            'data': {
                'normalized_data': stock_default,
                'corr_matrix': corr_default,
                'feasible_set': [],
                'efficient_frontier': [],
                'min_vol_portfolio': {'vp': 0.0, 'rp': 0.0},
                'market_portfolio': {'vp': 0.0, 'rp': 0.0},
                'risk_free_rate': 0.03,
                'stock_names': stocks
            }
        })


# ========== 启动服务 ==========
if __name__ == '__main__':
    # 确保数据库初始化
    init_db()
    app.run(
        host="0.0.0.0",  # 允许外部访问
        port=5000,  # 固定端口
        debug=False,  # 生产模式设为False
        threaded=True,  # 支持多线程
        use_reloader=False  # 禁用自动重载
    )
