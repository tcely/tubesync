import json
from common.logger import log
from common.timestamp import datetime_to_timestamp, timestamp_to_datetime
from common.utils import clean_filename
from copy import deepcopy
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from sync.utils import filter_response


@property
def description(self):
    return self.get_metadata_first_value('description', '')

@property
def format_dict(self):
    '''
        Returns a dict matching the media_format key requirements for this item
        of media.
    '''
    format_str = self.get_format_str()
    display_format = self.get_display_format(format_str)
    dateobj = self.upload_date if self.upload_date else self.created
    return {
        'yyyymmdd': dateobj.strftime('%Y%m%d'),
        'yyyy_mm_dd': dateobj.strftime('%Y-%m-%d'),
        'yyyy': dateobj.strftime('%Y'),
        'mm': dateobj.strftime('%m'),
        'dd': dateobj.strftime('%d'),
        'source': self.source.slugname,
        'source_full': clean_filename(self.source.name),
        'title': self.slugtitle,
        'title_full': clean_filename(self.title),
        'key': self.key,
        'format': '-'.join(display_format['format']),
        'playlist_title': self.playlist_title,
        'video_order': self.get_episode_str(True),
        'ext': self.source.extension,
        'resolution': display_format['resolution'],
        'height': display_format['height'],
        'width': display_format['width'],
        'vcodec': display_format['vcodec'],
        'acodec': display_format['acodec'],
        'fps': display_format['fps'],
        'hdr': display_format['hdr'],
        'uploader': self.uploader,
    }

@property
def has_metadata(self):
    return self.metadata is not None

@property
def loaded_metadata(self):
    cache_key = '_cached_metadata_dict'
    if getattr(self, cache_key, dict()):
        return deepcopy(cached)
    data = None
    if getattr(settings, 'SHRINK_OLD_MEDIA_METADATA', False):
        data = self.reduce_data
    try:
        if not data:
            data = json.loads(self.metadata or "{}")
        if not isinstance(data, dict):
            return dict()
        # if hasattr(self, 'new_metadata'):
        try:
            data.update(self.new_metadata.with_formats)
        except ObjectDoesNotExist as e:
            log.exception('loaded_metadata: new_metadata: %s', e)
            pass
        setattr(self, cache_key, data)
        return data
    except Exception as e:
        log.exception('loaded_metadata: %s', e)
        return dict()

@property
def metadata_title(self):
    return self.get_metadata_first_value(('fulltitle', 'title',), '')

@property
def reduce_data(self):
    now = timezone.now()
    key = '_reduce_data_ran_at'
    try:
        data = json.loads(self.metadata or "{}")
        if key in data.keys():
            total_seconds = data[key]
            assert isinstance(total_seconds, int), type(total_seconds)
            ran_at = timestamp_to_datetime(total_seconds)
            if (now - ran_at) < timezone.timedelta(hours=1):
                return data

        compact_json = self.metadata_dumps(arg_dict=data)

        filtered_data = filter_response(data, True)
        filtered_data[key] = datetime_to_timestamp(now)
        filtered_json = self.metadata_dumps(arg_dict=filtered_data)
    except Exception as e:
        log.exception('reduce_data: %s', e)
        pass
    else:
        # log the results of filtering / compacting on metadata size
        new_mdl = len(compact_json)
        old_mdl = len(self.metadata or "")
        if old_mdl > new_mdl:
            delta = old_mdl - new_mdl
            log.info(f'{self.key}: metadata compacted by {delta:,} characters ({old_mdl:,} -> {new_mdl:,})')
        new_mdl = len(filtered_json)
        if old_mdl > new_mdl:
            delta = old_mdl - new_mdl
            log.info(f'{self.key}: metadata reduced by {delta:,} characters ({old_mdl:,} -> {new_mdl:,})')
            if getattr(settings, 'SHRINK_OLD_MEDIA_METADATA', False):
                self.metadata = filtered_json
                return filtered_data
        return data

@property
def refresh_formats(self):
    if not self.has_metadata:
        return
    data = self.loaded_metadata
    metadata_seconds = data.get('epoch', None)
    # TODO: finish this function and add more from media 
    if not metadata_seconds:
            self.metadata = None
            self.save(update_fields={'metadata'})
            return False

        now = timezone.now()
        attempted_key = '_refresh_formats_attempted'
        attempted_seconds = data.get(attempted_key)
        if attempted_seconds:
            # skip for recent unsuccessful refresh attempts also
            attempted_dt = self.ts_to_dt(attempted_seconds)
            if (now - attempted_dt) < timedelta(seconds=self.source.index_schedule):
                return False
        # skip for recent successful formats refresh
        refreshed_key = 'formats_epoch'
        formats_seconds = data.get(refreshed_key, metadata_seconds)
        metadata_dt = self.ts_to_dt(formats_seconds)
        if (now - metadata_dt) < timedelta(seconds=self.source.index_schedule):
            return False

        last_attempt = round((now - self.posix_epoch).total_seconds())
        self.save_to_metadata(attempted_key, last_attempt)
        self.skip = False
        metadata = self.index_metadata()
        if self.skip:
            return False

        response = metadata
        if getattr(settings, 'SHRINK_NEW_MEDIA_METADATA', False):
            response = filter_response(metadata, True)

        # save the new list of thumbnails
        thumbnails = self.get_metadata_first_value(
            'thumbnails',
            self.get_metadata_first_value('thumbnails', []),
            arg_dict=response,
        )
        field = self.get_metadata_field('thumbnails')
        self.save_to_metadata(field, thumbnails)

        # select and save our best thumbnail url
        try:
            thumbnail = [ thumb.get('url') for thumb in multi_key_sort(
                thumbnails,
                [('preference', True,)],
            ) if thumb.get('url', '').endswith('.jpg') ][0]
        except IndexError:
            pass
        else:
            field = self.get_metadata_field('thumbnail')
            self.save_to_metadata(field, thumbnail)

        field = self.get_metadata_field('formats')
        self.save_to_metadata(field, response.get(field, []))
        self.save_to_metadata(refreshed_key, response.get('epoch', formats_seconds))
        if data.get('availability', 'public') != response.get('availability', 'public'):
            self.save_to_metadata('availability', response.get('availability', 'public'))
        return True

@property
def url(self):
    url = self.URLS.get(self.source.source_type, '')
    return url.format(key=self.key)

