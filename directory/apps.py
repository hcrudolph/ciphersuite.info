from django.apps import AppConfig


class DirectoryConfig(AppConfig):
    name = 'directory'
    def ready(self):
        import directory.signals