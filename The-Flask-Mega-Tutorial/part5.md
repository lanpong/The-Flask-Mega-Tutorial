The Flask Mega-Tutorial Part V: User Logins
===
原文地址：[The Flask Mega-Tutorial Part V: User Logins](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-v-user-logins)

这是Flask Mega-Tutorial系列的第五部分，我将告诉你如何创建一个用户登录子系统。

在[第3章](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iii-web-forms)中，你学习了如何创建用户登录表单，并在[第4章](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database)中学习了如何使用数据库。本章将教你如何结合这两章的主题来创建一个简单的用户登录系统。

本章的Github链接是：[Browse](https://github.com/miguelgrinberg/microblog/tree/v0.5), [Zip](https://github.com/miguelgrinberg/microblog/archive/v0.5.zip), [Diff](https://github.com/miguelgrinberg/microblog/compare/v0.4...v0.5)

哈希密码
===

在第4章中，用户模型被赋值给了一个 `password_hash` 字段，到目前为止还没有被使用。这个字段的目的是保存用户密码的哈希值，用来验证用户在登录过程中输入的密码。Password hashing 是一个应该由安全专家来决定复杂话题，但是有几个易于使用的库以一种简单的方式调用应用程序来实现所有的逻辑。

其中一个实现哈希密码的包是 [Werkzeug](http://werkzeug.pocoo.org/)，当你安装 Flask 时，因为它是一个核心依赖，你可能会在 pip 的输出中看到这个包。由于它是依赖项，Werkzeug 已经安装在您的虚拟环境中。下面在 Python shell 中演示如何进行密码的哈希：

```
>>> from werkzeug.security import generate_password_hash
>>> hash = generate_password_hash('foobar')
>>> hash
'pbkdf2:sha256:50000$vT9fkZM8$04dfa35c6476acf7e788a1b5b3c35e217c78dc04539d295f011f01f18cd2175f'
```

在这个例子中，密码 `foobar` 通过一系列未知的反向操作和加密操作被转换成一个长编码的字符串，这意味着获得密码哈希值的人将无法使用它来获得原始密码。当然还有额外的防护措施，如果你多次哈希相同的密码，你将得到不同的结果，所以这使得无法通过查看密码的的哈希值来确定两个用户是否具有相同的密码。

验证过程使用 Werkzeug 的第二个函数完成，如下所示：

```python
>>> from werkzeug.security import check_password_hash
>>> check_password_hash(hash, 'foobar')
True
>>> check_password_hash(hash, 'barfoo')
False
```

验证功能采用之前生成的哈希值以及用户在登录时输入的密码。如果用户提供的密码与哈希值匹配，则函数返回 `True`，否则返回 `False`。

整个密码哈希过程可以在用户模型中用两个新的方法实现：

```python
from werkzeug.security import generate_password_hash, check_password_hash

# ...

class User(db.Model):
    # ...

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
```

使用这两种方法，用户对象现在可以执行安全的密码验证，而不需要永久存储原始密码。以下是这些新方法的示例用法：

```python
>>> u = User(username='susan', email='susan@example.com')
>>> u.set_password('mypassword')
>>> u.check_password('anotherpassword')
False
>>> u.check_password('mypassword')
True
```

Flask-Login 简介
===

在本章中，我将向你介绍一种非常流行的名为 [Flask-Login](https://flask-login.readthedocs.io/) 的 Flask 扩展。此扩展用于管理用户登录状态，例如：用户可以登录到应用程序，然后导航到不同的页面，而应用程序“remembers”用户已登录。它还提供了“remember me”功能，即使在关闭浏览器窗口之后，用户仍可以保持登录状态。为了准备好本章，您可以先在您的虚拟环境中安装 Flask-Login：

```
(venv) $ pip install flask-login
```

和其他扩展一样，Flask-Login 需要在 *app/__init__.py* 中的应用实例之后被创建和初始化。下面是这是这个扩展如何初始化的：

```python
#...
from flask_login import LoginManager

app = Flask(__name__)
# ...
login = LoginManager(app)

# ...
```

为 Flask-Login 准备用户模型
===

Flask-Login 扩展与应用的用户模型一起工作，并期望在其中实现某些属性和方法。这种方法很好，因为只要将这些必需项添加到模型中，Flask-Login 就没有其他要求，例如，它可以和基于任何数据库系统的用户模型一起工作。

下面列出了四个必需项目：

- `is_authenticated`：如果用户具有有效凭证，则为`True`，否则为`False`。
- `is_active`：如果用户的帐户处于活动状态，则为`True`，否则为`False`。
- `is_anonymous`：常规用户为`False`的属性，特殊匿名用户为`True`。
- `get_id()`：为用户返回唯一标识符的方法（如果使用Python2，则为unicode）。

我可以很容易地实现这四个，但由于实现相当通用，Flask-Login 提供了一个名为 `UserMixin` 的混合类，它包括适用于大多数用户模型类的泛型实现。下面是如何将 mixin 类添加到模型中：

```python
# ...
from flask_login import UserMixin

class User(UserMixin, db.Model):
    # ...
```

User Loader Function
===

Flask-Login 通过在 Flask 的用户会话中存储其唯一标识符来跟踪登录的用户，该用户会话是分配给连接到应用的每个用户的存储空间。每次登录用户导航到新页面时，Flask-Login 将从会话中检索用户的 ID，然后将该用户加载到内存中。

因为 Flask-Login 对数据库一无所知，所以需要应用的帮助来加载用户。因此，扩展期望应用程序将配置一个用户加载函数，可以调用该函数来加载给定 ID 的用户。这个功能可以添加到 *app/models.py* 中：

```python
from app import login
# ...

@login.user_loader
def load_user(id):
    return User.query.get(int(id))
```

用户加载器使用 `@login.user_loader` 修饰器在Flask-Login上注册。Flask-Login 中作为参数传递给函数的 `id` 将是一个字符串，所以使用数字 ID 的数据库需要将字符串转换为整数，如上所示。

Logging Users In
===

让我们回顾一下登录视图功能，就像你记得的那样，这个功能实现了一个虚假登录，它只是发出一个 `flash()` 消息。现在，应用程序可以访问用户数据库，并知道如何生成和验证密码哈希，这个视图功能可以完成。

```python
# ...
from flask_login import current_user, login_user
from app.models import User

# ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)
```

`login()`函数中的前两行处理一个奇怪的情况。假设您有一个已经登录的用户，并且用户导航到您的应用程序的*/login* URL。显然这是一个错误，所以我不想这样做。`current_user`变量来自Flask-Login，可以在处理过程中随时使用，以获取代表请求客户端的用户对象。这个变量的值可以是数据库中的一个用户对象（Flask-Login通过我上面提供的用户加载器回调读取），或者如果用户还没有登录，则是一个特殊的匿名用户对象。记住那些在用户对象中需要Flask-Login的属性？其中之一是`is_authenticated`，它可以方便地检查用户是否登录。当用户已经登录，我只是重定向到索引页面。

代替之前使用的`flash()`调用，现在我可以将用户登录为真实的。第一步是从数据库加载用户。用户名附带表单提交，所以我可以查询数据库以找到用户。为此，我使用SQLAlchemy查询对象的`filter_by()`方法。`filter_by()`的结果是一个只包含具有匹配用户名的对象的查询。因为我知道只有一个或零个结果，所以我通过调用`first()`来完成查询，如果它存在，将返回用户对象;如果不存在，则返回None。在[第4章](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database)中，您已经看到，当您在查询中调用`all()`方法时，将执行查询，并获取与该查询匹配的所有结果的列表。`first()`方法是执行查询的另一个常用方法，只需要有一个结果。

如果我得到了所提供的用户名的匹配，我可以接下来检查表单中随附的密码是否有效。这是通过调用上面定义的`check_password()`方法来完成的。这将采用与用户一起存储的密码散列，并确定在表单中输入的密码是否与散列匹配。所以，现在我有两个可能的错误情况：用户名可能是无效的，或者密码可能是不正确的用户。在这两种情况下，我都会刷新一条消息，然后重定向到登录提示符，以便用户可以再次尝试。

如果用户名和密码都是正确的，那么我调用来自Flask-Login的`login_user()`函数。这个函数将把用户注册为登录，这意味着用户导航到的任何未来页面都会将`current_user`变量设置为该用户。

为了完成登录过程，我只是将新登录的用户重定向到索引页面。

Logging Users Out
===

我知道我还需要为用户提供注销应用程序的选项。这可以通过Flask-Login的`logout_user()`函数来完成。这里是注销视图功能：

```python
# ...
from flask_login import logout_user

# ...

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
```

为了向用户公开这个链接，我可以让用户登录后，导航栏中的登录链接自动切换到注销链接。这可以在base.html模板中使用条件来完成：

```html
    <div>
        Microblog:
        <a href="{{ url_for('index') }}">Home</a>
        {% if current_user.is_anonymous %}
        <a href="{{ url_for('login') }}">Login</a>
        {% else %}
        <a href="{{ url_for('logout') }}">Logout</a>
        {% endif %}
    </div>
```

`is_anonymous`属性是Flask-Login通过`UserMixin`类向用户对象添加的属性之一。仅当用户未登录时，`current_user.is_anonymous`表达式才会为`True`。

Requiring Users To Login
===

Flask-Login提供了一个非常有用的功能，强制用户在查看应用程序的特定页面之前登录。如果没有登录的用户尝试查看受保护的页面，Flask-Login将自动将用户重定向到登录表单，并且只有在登录过程完成后才重定向到用户想查看的页面。

为了实现这个功能，Flask-Login需要知道处理登录的视图函数是什么。这可以在*app/__init__.py*中添加：

```python
# ...
login = LoginManager(app)
login.login_view = 'login'
```

上面的`'login'`值是登录视图的功能（或端点）名称。换句话说，您将在`url_for()`调用中使用的名称来获取URL。

Flask-Login保护匿名用户的视图函数的方法是使用名为`@login_required`的修饰器。当您将此装饰器添加到Flask的`@app.route`装饰器下的视图函数时，该函数将变为受保护的，并且将不允许访问未通过身份验证的用户。以下是装饰器如何应用于应用程序的索引视图功能：

```python
from flask_login import login_required

@app.route('/')
@app.route('/index')
@login_required
def index():
    # ...
```

剩下的就是实现从成功登录到用户想要访问的页面的重定向。当一个没有登录的用户访问一个被 `@login_required` 装饰器保护的视图函数时，装饰器将重定向到登录页面，但是它将在这个重定向中包含一些额外的信息，以便应用程序可以返回第一页。例如，如果用户导航到*/index*，那么`@login_required`装饰器将拦截请求并以重定向到/ login的方式进行响应，但它会向这个URL添加一个查询字符串参数，从而完成重定向URL */login?next=/next*。`next` 查询字符串参数被设置为原始URL，因此应用程序可以在登录后使用它重定向回去。

下面是一段代码，展示了如何读取和处理 `next` 查询字符串参数：

```python
from flask import request
from werkzeug.urls import url_parse

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ...
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    # ...
```

在用户通过调用`Flask-Login`的`login_user()`函数登录之后，获取下一个查询字符串参数的值。Flask提供一个 `request` 变量，其中包含客户端随请求发送的所有信息。特别是，`request.args`属性以友好的字典格式公开查询字符串的内容。实际上有三种可能的情况需要考虑，以确定成功登录后重定向的位置：

- 如果登录URL没有`next`参数，则用户被重定向到索引页面。
- 如果登录URL包含设置为相对路径的`next`参数（换句话说，没有域部分的URL），则用户被重定向到该URL。
- 如果登录URL包含`next`设置为包含域名的完整URL的参数，则用户将被重定向到索引页面。

第一和第二种情况是不言自明的。第三种情况是为了使申请更安全。攻击者可以在`next`参数中插入一个恶意站点的URL，这样应用程序只在URL相对时才重定向，这可以确保重定向与应用程序保持在同一个站点。要确定URL是相对的还是绝对的，我使用Werkzeug的`url_parse()`函数解析它，然后检查`netloc`组件是否被设置。

Showing The Logged In User in Templates
===

你是否还记得[第2章](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-ii-templates)中的那个方法？我创建了一个假的用户来帮助我在用户子系统到位之前设计应用程序的主页？那么，应用程序现在有真正的用户，所以我现在可以删除假用户，并开始与真正的用户工作。而不是假的用户，我可以在模板中使用Flask-Login的`current_user`：

```html
{% extends "base.html" %}

{% block content %}
    <h1>Hi, {{ current_user.username }}!</h1>
    {% for post in posts %}
    <div><p>{{ post.author.username }} says: <b>{{ post.body }}</b></p></div>
    {% endfor %}
{% endblock %}
```

我可以删除视图函数中的`user`模板参数：

```python
@app.route('/')
@app.route('/index')
def index():
    # ...
    return render_template("index.html", title='Home Page', posts=posts)
```

这是测试登录和注销功能如何工作的好时机。由于仍然没有用户注册，所以要将用户添加到数据库的唯一方法是通过Python shell执行此操作，请运行`flask shell`并输入以下命令来注册用户：

```python
>>> u = User(username='susan', email='susan@example.com')
>>> u.set_password('cat')
>>> db.session.add(u)
>>> db.session.commit()
```

如果启动应用程序并尝试访问*http://localhost:5000/* 或 *http://localhost:5000/index*，则会立即重定向到登录页面，并且在使用用户的凭据你添加到你的数据库，你将被返回到原来的页面，在其中你会看到一个个性化的问候语。

User Registration
===

本章要构建的最后一项功能是注册表单，以便用户可以通过Web表单注册自己。我们首先在*app/forms.py*中创建Web窗体类：

```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User

# ...

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
```

这种与验证有关的新形式中有一些有趣的事情。首先，对于`email`，我在`DataRequired`之后添加了第二个验证器，称为`Email`。这是WTForms附带的另一个股票验证器，它将确保用户在此字段中键入的内容与电子邮件地址的结构相匹配。

由于这是一个注册表，习惯上要求用户输入密码两次，以减少错字的风险。为此，我有`password`和`password2`字段。第二个密码字段使用另一个名为`EqualTo`的股票验证器，它将确保其值与第一个密码字段的值相同。

我还为这个类添加了两个方法：`validate_username()` 和 `validate_email()`。当添加任何匹配模式`validate_<field_name>`的方法时，WTForms将这些方法作为自定义验证器并除了股票验证器之外调用它们。在这种情况下，我想确保用户输入的用户名和电子邮件地址不在数据库中，所以这两个方法发出数据库查询，期望没有结果。如果结果存在，则通过引发`ValidationError`来触发验证错误。在例外中包含作为参数的消息将是将在用户看到的字段旁边显示的消息。

为了在网页上显示这个表单，我需要一个HTML模板，我将把它存储在*app/templates/register.html*文件中。这个模板的构造与登录表单类似：

```html
{% extends "base.html" %}

{% block content %}
    <h1>Register</h1>
    <form action="" method="post">
        {{ form.hidden_tag() }}
        <p>
            {{ form.username.label }}<br>
            {{ form.username(size=32) }}<br>
            {% for error in form.username.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.email.label }}<br>
            {{ form.email(size=64) }}<br>
            {% for error in form.email.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.password.label }}<br>
            {{ form.password(size=32) }}<br>
            {% for error in form.password.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.password2.label }}<br>
            {{ form.password2(size=32) }}<br>
            {% for error in form.password2.errors %}
            <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>{{ form.submit() }}</p>
    </form>
{% endblock %}
```
登录表单模板需要一个链接，将新用户发送到注册表单，正下方的表单：

```html
    <p>New User? <a href="{{ url_for('register') }}">Click to Register!</a></p>
```
最后，我需要编写将在 *app/routes.py*  中处理用户注册的视图函数：

```python
from app import db
from app.forms import RegistrationForm

# ...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
```
而这个视图功能也应该大部分是不言自明的。我首先确保调用这个路由的用户没有登录。表单处理方式与登录方式相同。在 `if validate_on_submit()` 条件下完成的逻辑将使用提供的用户名，电子邮件和密码创建一个新用户，将其写入数据库，然后重定向到登录提示，以便用户可以登录。

![](https://blog.miguelgrinberg.com/static/images/mega-tutorial/ch05-register-form.png)

通过这些更改，用户应该能够在此应用程序上创建帐户，并登录和注销。请确保您尝试了我在注册表单中添加的所有验证功能，以便更好地了解其工作原理。我将在未来的章节中重新审视用户认证子系统，以增加额外的功能，例如允许用户在忘记密码的情况下重置密码。但现在，这足以继续构建应用程序的其他领域。