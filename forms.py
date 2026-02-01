from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length


class SelfAssessmentForm(FlaskForm):
    q1 = TextAreaField(
        "What emotions have you been experiencing most recently?",
        validators=[DataRequired(), Length(min=5)]
    )

    q2 = TextAreaField(
        "What is one personal strength you are proud of?",
        validators=[DataRequired(), Length(min=5)]
    )

    submit = SubmitField("Submit")