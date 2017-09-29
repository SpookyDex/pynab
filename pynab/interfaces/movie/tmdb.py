import requests
import difflib

from pynab import log
import pynab.ids
import config


API_KEY = config.postprocess.get('tmdb_api_key')
TMDB_SEARCH_URL = 'https://api.themoviedb.org/3/search/movie?api_key=' + API_KEY + '&query='
NAME = 'TMDB'


def search(data):
    """
    Search OMDB for an id based on a name/year.

    :param data: {name, year}
    :return: id
    """

    name = data['name']
    year = data['year']

    # if we managed to parse the year from the name
    # include it, since it'll narrow results
    if year:
        year_query = '&y={}'.format(year.replace('(', '').replace(')', ''))
    else:
        year_query = ''

    try:
        result = requests.get(TMDB_SEARCH_URL + name + year_query).json()
    except:
        log.critical('There was a problem accessing the IMDB API page.')
        return None

    if 'results' in result:
        for movie in result['results']:
            ratio = difflib.SequenceMatcher(None, pynab.ids.clean_name(name), pynab.ids.clean_name(movie['title'])).ratio()
            if ratio > 0.8 and year in movie['release_date']:
                temp = requests.get('https://api.themoviedb.org/3/movie/{}'.format(movie['id']) + '?api_key=' + API_KEY).json()
                return temp['imdb_id']
    return None

