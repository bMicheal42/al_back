from flask import current_app
from werkzeug.datastructures import MultiDict

from alerta.exceptions import ApiError


class Page:

    def __init__(self, page: int = 1, page_size: int = None, items: int = 0) -> None:

        self.page = page
        self.page_size = page_size or current_app.config['DEFAULT_PAGE_SIZE']
        self.items = items

        if items and self.page > self.pages or self.page < 1:
            raise ApiError(f'page out of range: 1-{self.pages}', 416)

    @staticmethod
    def from_params(params: MultiDict, items: int) -> 'Page':
        # page, page-size, limit (deprecated)
        try:
            page = int(params.get('page', 1))
            limit = int(params.get('limit', 0))
            page_size = int(params.get('page-size', limit))
            return Page(page, page_size, items)
        except:
            return ApiError('we')

    @property
    def pages(self) -> int:
        return ((self.items - 1) // self.page_size) + 1

    @property
    def has_more(self) -> bool:
        return self.page < self.pages
