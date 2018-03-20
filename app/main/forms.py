from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField, ValidationError
from wtforms.validators import DataRequired, Length, Email, Regexp
from ..models import User, Role
from flask_pagedown.fields import PageDownField

class NameForm(FlaskForm):
	name = StringField('What is your name?', validators=[DataRequired()]) # DataRequired 函数会捕捉没有输入内容的错误
	submit = SubmitField('Submit')

# 用戶的資料編輯表單
class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')


# 管理员使用的资料编辑表单
class EditProfileAdminForm(FlaskForm):
	email = StringField('Email', validators=[
		DataRequired(),
		Length(1, 64),
		Email()
	])
	username = StringField('Username', validators=[
		DataRequired(),
		Length(1, 64),
		Regexp(
			'^[A-Za-z][A-Za-z0-9_.]*$',
			0,
			'Usernames must have only letters, numbers, dots or underscores'
		)
	])
	confirmed = BooleanField('Confirmed')
	role = SelectField('Role', coerce=int)
	name = StringField('Real name', validators=[Length(0, 64)])
	location = StringField('Location', validators=[Length(0, 64)])
	about_me = TextAreaField('About me')
	submit = SubmitField('Submit')

	def __init__(self, user, *args, **kwargs):
		super(EditProfileAdminForm, self).__init__(*args, **kwargs)
		self.role.choices = [
			(role.id, role.name) for role in Role.query.order_by(Role.name).all()
			]
		self.user = user

	def validate_email(self, field):
		if field.data != self.user.email and User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

	def validate_username(self, field):
		if field.data != self.user.username and User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use.')

# 博客文章表单
class PostForm(FlaskForm):
    body = PageDownField("what's on your mind?", validators=[DataRequired()])
    submit = SubmitField('Submit')

# 評論表單
class CommentForm(FlaskForm):
    body = StringField('Enter your comment', validators=[DataRequired()])
    submit = SubmitField('Submit')
