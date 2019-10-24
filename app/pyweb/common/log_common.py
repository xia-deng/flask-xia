import logging
import os
from logging import FileHandler

from flask.globals import current_app

import config


class LogCommon():
    def get_path(self, basefile, filename):
        config_name = 'config.py' if basefile is None else basefile
        path = os.path.realpath(config.__file__)
        print(path)
        path = path[:path.index(config_name)]
        path = path + filename
        return path

    def init_log(self, app, log_name):
        log_path = self.get_path(None, log_name)
        file_handler = FileHandler(filename=log_path, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        return app

    @staticmethod
    def print_log_error(msg):
        current_app.logger.error(msg)

    @staticmethod
    def print_log_warn(msg):
        current_app.logger.warn(msg)

    @staticmethod
    def print_log_info(msg):
        current_app.logger.info(msg)
