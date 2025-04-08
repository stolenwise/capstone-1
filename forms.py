from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, URLField, BooleanField, SubmitField, PasswordField
from wtforms.validators import Optional, InputRequired, URL, DataRequired, Email

from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField
from wtforms.validators import InputRequired, Optional, AnyOf, URL, NumberRange

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()]) 
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class AddBookForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired()])
    genre = StringField(
        "Genre",
        validators=[InputRequired(), AnyOf(["Fiction", "Non-Fiction"], message="Species must be Fiction or Non-Fiction")]
    )
    cover_url = StringField(
        "Cover URL",
        validators=[Optional(), URL(message="Must be a valid URL")]
    )
    # page_count = IntegerField(
    #     "Page Count",
    #     validators=[Optional(), IntegerField(min=1, max=3000, message="Page count must be between 1 and 3000")]
    # )
    description = TextAreaField("Description", validators=[Optional()])



class EditBookForm(FlaskForm):
    cover_url = StringField("Cover URL", validators=[Optional(), URL()])
    description = TextAreaField("Notes", validators=[Optional()])
    available = BooleanField("Available?")