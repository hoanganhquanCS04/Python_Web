from django.contrib import admin
from .models import Comment, Forum, Material, Subject, VideoLecture, Quiz, Examine, Question, Option, StudentAnswer, SearchHistory


admin.site.register(Material)
admin.site.register(VideoLecture)
admin.site.register(Subject)
admin.site.register(Quiz)
admin.site.register(SearchHistory)  
