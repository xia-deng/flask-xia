from flask import render_template, request, jsonify

from app.pyweb.main import main


class HttpError:
    Error_404 = {'errorCode': '404', 'errorMsg': 'page or resource not found'}
    Error_500 = {'errorCode': '500', 'errorMsg': 'internal server error'}
    Error_403 = {'errorCode': '403', 'errorMsg': 'forbidden'}


@main.app_errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        response = jsonify(HttpError.Error_404)
        response.status_code = 404
        return response
    return render_template('404.html'), 404


@main.app_errorhandler(403)
def page_forbidden(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        response = jsonify(HttpError.Error_403)
        response.status_code = 403
        return response
    return render_template('403.html'), 403


@main.app_errorhandler(500)
def internal_server_error(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        response = jsonify(HttpError.Error_500)
        response.status_code = 500
        return response
    return render_template('404.html'), 500
