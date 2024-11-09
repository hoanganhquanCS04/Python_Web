from django.db import models
from django.conf import settings  # Sử dụng AUTH_USER_MODEL cho model User tùy chỉnh

# Comment model
class Comment(models.Model):
    forum = models.ForeignKey('Forum', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

# Forum model   
class Forum(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=1)  # Default for migration
    title = models.CharField(max_length=200, default="Untitled Forum")
    description = models.TextField(default="No description")
    created_at = models.DateTimeField(auto_now_add=True)

# Material model
class Material(models.Model):
    subject = models.ForeignKey('Subject', on_delete=models.CASCADE, default=1)  # Default Subject for migration
    title = models.CharField(max_length=200, default="Untitled Material")
    type = models.CharField(max_length=50, default="General")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=1)  # Default Author
    url = models.URLField(max_length=200, default="http://example.com")
    description = models.TextField(default="No description available")

    @property
    def get_type(self):
        return 'material'

# Subject model
class Subject(models.Model):
    subject_name = models.CharField(max_length=100, default="Untitled Subject")
    description = models.TextField(default="No description available")
    credit = models.BigIntegerField(default=3)

# VideoLecture model


class VideoLecture(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, default=1)
    video_name = models.CharField(max_length=200, default="Untitled Video")
    iframe = models.TextField(default="No iframe content")
    description = models.TextField(default="No description available")

    # Phương thức trả về tên video làm title
    @property
    def title(self):
        return self.video_name

    # Phương thức trả về iframe làm url
    @property
    def url(self):
        # Tách và lấy đường dẫn từ thẻ iframe
        if 'src=' in self.iframe:
            start = self.iframe.find('src=') + 5
            end = self.iframe.find("'", start)
            return self.iframe[start:end]
        return '#'

    @property
    def get_type(self):
        return 'video'

# Quiz model
class Quiz(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, default=1)
    quiz_name = models.CharField(max_length=100, default="Untitled Quiz")
    description = models.TextField(default="No description")

# Examine model
class Examine(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=1)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, default=1)
    score = models.FloatField(default=0.0)
    correct_answers = models.IntegerField(default=0)
    incorrect_answers = models.IntegerField(default=0)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(auto_now_add=True)

# Question model
class Question(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, default=1)
    content = models.TextField(default="No content")
    question_type = models.BigIntegerField(default=0)

# Option model
class Option(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, default=1)
    is_correct = models.BooleanField(default=False)
    content = models.TextField(default="No content")

# StudentAnswer model
class StudentAnswer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, default=1)
    quiz_result = models.ForeignKey(Examine, on_delete=models.CASCADE, default=1)
    answer_text = models.TextField(default="No answer provided")
    score = models.FloatField(default=0.0)
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=1)

class SearchHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # Người dùng thực hiện tìm kiếm
    query = models.CharField(max_length=255)  # Từ khóa tìm kiếm
    timestamp = models.DateTimeField(auto_now_add=True)  # Thời gian tìm kiếm

    def __str__(self):
        return f"{self.user.get_full_name} searched for '{self.query}' on {self.timestamp}"