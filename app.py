from typing import Tuple, Union

from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'secret_api_key_aaa'  

db = SQLAlchemy(app)
jwt = JWTManager(app)
api = Api(app, version='1.0', title='Task Manager API', description='API для управления задачами с пользователями')

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tasks')

db.create_all()

# Модели для документации
user_model = api.model('User', {
    'username': fields.String(required=True, description='Имя пользователя'),
    'password': fields.String(required=True, description='Пароль пользователя')
})

task_model = api.model('Task', {
    'id': fields.Integer(readonly=True, description='Уникальный идентификатор задачи'),
    'title': fields.String(required=True, description='Заголовок задачи'),
    'description': fields.String(description='Описание задачи'),
    'done': fields.Boolean(description='Статус выполнения задачи')
})

# Пространства имен
auth_ns = api.namespace('auth', description='Аутентификация')
tasks_ns = api.namespace('tasks', description='Операции с задачами')

# Эндпоинты для аутентификации
@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(user_model, validate=True)
    def post(self) -> Tuple[dict, int]:
        """Регистрация нового пользователя"""
        data = request.json
        if User.query.filter_by(username=data['username']).first():
            return {'message': 'Пользователь уже существует'}, 400
        
        hashed_password = generate_password_hash(data['password'])
        new_user = User(username=data['username'], password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'Пользователь зарегистрирован'}, 201

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(user_model, validate=True)
    def post(self) -> Tuple[dict, int]:
        """Авторизация пользователя"""
        data = request.json
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        return {'message': 'Неверное имя пользователя или пароль'}, 401

# Эндпоинты для задач
@tasks_ns.route('/')
class TaskList(Resource):
    @jwt_required()
    @tasks_ns.marshal_list_with(task_model)
    def get(self) -> Tuple[list, int]:
        """Получение списка всех задач для текущего пользователя"""
        user_id = get_jwt_identity()
        tasks = Task.query.filter_by(user_id=user_id).all()
        return tasks, 200

    @jwt_required()
    @tasks_ns.expect(task_model, validate=True)
    @tasks_ns.marshal_with(task_model, code=201)
    def post(self) -> Tuple[Task, int]:
        """Создание новой задачи"""
        user_id = get_jwt_identity()
        data = request.json
        new_task = Task(title=data['title'], description=data.get('description'), user_id=user_id)
        db.session.add(new_task)
        db.session.commit()
        return new_task, 201

@tasks_ns.route('/<int:task_id>')
@tasks_ns.response(404, 'Задача не найдена')
class TaskResource(Resource):
    @jwt_required()
    @tasks_ns.marshal_with(task_model)
    def get(self, task_id: int) -> Union[Tuple[Task, int], Tuple[dict, int]]:
        """Получение информации о задаче по ID"""
        user_id = get_jwt_identity()
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        if not task:
            api.abort(404, "Задача не найдена")
        return task, 200

    @jwt_required()
    @tasks_ns.expect(task_model, validate=True)
    @tasks_ns.marshal_with(task_model)
    def put(self, task_id: int) -> Union[Tuple[Task, int], Tuple[dict, int]]:
        """Обновление задачи"""
        user_id = get_jwt_identity()
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        if not task:
            api.abort(404, "Задача не найдена")
        data = request.json
        task.title = data.get('title', task.title)
        task.description = data.get('description', task.description)
        task.done = data.get('done', task.done)
        db.session.commit()
        return task, 200

    @jwt_required()
    @tasks_ns.response(204, 'Задача удалена')
    def delete(self, task_id: int) -> Tuple[str, int]:
        """Удаление задачи"""
        user_id = get_jwt_identity()
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        if not task:
            api.abort(404, "Задача не найдена")
        db.session.delete(task)
        db.session.commit()
        return '', 204

# Запуск приложения
if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)

