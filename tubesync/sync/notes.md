Media:
- thumbpath
- nfopath
- jsonpath
- filepath
- thumb.path
- media_file.path


Metadata mappings:
```
{
'upload_date': 'upload_date',
'title': 'title',
'thumbnail': 'thumbnail',
'description': 'description',
'duration': 'duration',
'formats': 'formats',
'categories': 'categories',
'uploader': 'uploader',
'upvotes': 'like_count',

# no actual values in my db
'rating': 'average_rating',
'age_limit': 'age_limit',
'downvotes': 'dislike_count',
'playlist_title': 'playlist_title',
}
```


Because of an optimization the signal isn't always triggered, see 'delete' at: https://docs.djangoproject.com/en/3.2/_modules/django/db/models/deletion/

