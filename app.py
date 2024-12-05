from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 設定一個密鑰

# 設定資料庫
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 初始化登入管理
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 用戶模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# 記帳紀錄模型
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 首頁路由
@app.route('/')
@login_required
def index():
    expenses = Expense.query.all()
    return render_template('index.html', expenses=expenses)

# 註冊路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        
        try:
            db.session.commit()
            flash('註冊成功！現在可以登入了。')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()  # Rollback the session to maintain consistency
            flash('該用戶名已存在，請選擇其他用戶名。')
            return redirect(url_for('register'))
    
    return render_template('register.html')


# 登入路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('登入失敗，請檢查帳號密碼。')
    return render_template('login.html')

# 登出路由
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('您已登出')
    return redirect(url_for('login'))

# 添加記帳紀錄的路由
@app.route('/add', methods=['POST'])
@login_required
def add_expense():
    amount = request.form.get('amount')
    category = request.form.get('category')
    description = request.form.get('description')

    new_expense = Expense(amount=amount, category=category, description=description)
    db.session.add(new_expense)
    db.session.commit()
    return redirect(url_for('index'))

# 刪除記帳紀錄的路由
@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):
    expense_to_delete = Expense.query.get_or_404(id)
    db.session.delete(expense_to_delete)
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 建立資料表
    app.run(debug=True)
