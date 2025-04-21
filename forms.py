from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, URLField, BooleanField, FileField, SubmitField, PasswordField
from wtforms.validators import Optional, InputRequired, URL, DataRequired, Email, AnyOf
from flask_wtf.file import FileAllowed, FileRequired
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, SelectField
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
    genre = SelectField("Genre", 
                       choices=[
                           ('', '-- Select a Genre --'),  # Empty default option
                           ('Fiction', 'Fiction'),
                           ('Non-Fiction', 'Non-Fiction'),
                           ('Religious', 'Religious'),
                           ('Philosophy', 'Philosophy'),
                           ('History', 'History'),
                           ('Psychology', 'Psychology'),
                           ('Science Fiction', 'Science Fiction'),
                           ('Fantasy', 'Fantasy'),
                           ('Mystery', 'Mystery'),
                           ('Romance', 'Romance'),
                           ('Biography', 'Biography')
                       ],
                       validators=[InputRequired()])
    
    cover_url = StringField(
        "Cover URL",
        validators=[Optional(), URL(message="Must be a valid URL")]
    )
    author = StringField("Author", validators=[InputRequired()])
    description = TextAreaField("Description", validators=[Optional()])

    # Add the file upload field here
    file = FileField('Book File', validators=[FileAllowed(['pdf', 'epub'], 'PDF or EPUB files only!')])
    submit = SubmitField("Add Book")



class EditBookForm(FlaskForm):
    cover_url = StringField("Cover URL", validators=[Optional(), URL()])
    description = TextAreaField("Notes", validators=[Optional()])
    available = BooleanField("Available?")