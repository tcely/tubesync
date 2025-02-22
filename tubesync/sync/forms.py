
from django import forms
from django.utils.translation import gettext_lazy as _


class ValidateSourceForm(forms.Form):

    source_type = forms.CharField(
        max_length=1,
        required=True,
        widget=forms.HiddenInput()
    )
    source_url = forms.URLField(
        label=_('Source URL'),
        required=True
    )


class ConfirmDeleteSourceForm(forms.Form):

    delete_media = forms.BooleanField(
        label=_('Also delete downloaded media'),
        required=False
    )


class RedownloadMediaForm(forms.Form):

    pass


class SkipMediaForm(forms.Form):

    pass


class EnableMediaForm(forms.Form):

    pass


class ResetTasksForm(forms.Form):

    pass


class ConfirmDeleteMediaServerForm(forms.Form):

    pass

_media_server_type_label = 'Jellyfin'
class JellyfinMediaServerForm(forms.Form):

    host = forms.CharField(
        label=_(f'Host name or IP address of the {_media_server_type_label} server'),
        required=True,
    )
    port = forms.IntegerField(
        label=_(f'Port number of the {_media_server_type_label} server'),
        required=True,
        initial=8096,
    )
    use_https = forms.BooleanField(
        label=_('Connect over HTTPS'),
        required=False,
        initial=False,
    )
    verify_https = forms.BooleanField(
        label=_('Verify the HTTPS certificate is valid if connecting over HTTPS'),
        required=False,
        initial=True,
    )
    token = forms.CharField(
        label=_(f'{_media_server_type_label} token'),
        required=True,
    )
    libraries = forms.TextField(
        label=_(f'Comma-separated list of {_media_server_type_label} library IDs to update'),
        required=False,
    )


_media_server_type_label = 'Plex'
class PlexMediaServerForm(forms.Form):

    host = forms.CharField(
        label=_('Host name or IP address of the Plex server'),
        required=True
    )
    port = forms.IntegerField(
        label=_('Port number of the Plex server'),
        required=True,
        initial=32400
    )
    use_https = forms.BooleanField(
        label=_('Connect over HTTPS'),
        required=False,
        initial=True,
    )
    verify_https = forms.BooleanField(
        label=_('Verify the HTTPS certificate is valid if connecting over HTTPS'),
        required=False
    )
    token = forms.CharField(
        label=_('Plex token'),
        required=True
    )
    libraries = forms.CharField(
        label=_('Comma-separated list of Plex library IDs to update, such as "9" or "4,6"')
    )
