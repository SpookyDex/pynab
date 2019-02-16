import concurrent.futures
import time
import traceback
import datetime

import pytz

from pynab import log, log_init
from pynab.db import db_session, Release, Blacklist, Group, MetaBlack, NZB, NFO, SFV, vacuum
import pynab.groups
import pynab.binaries
import pynab.releases
import pynab.rars
import pynab.nfos
import pynab.sfvs
import pynab.requests
import pynab.ids
import scripts.quick_postprocess
import scripts.rename_bad_releases
import config


def process_tvshows():
    try:
        return pynab.ids.process('tv', interfaces=config.postprocess.get('process_tvshows'), limit=500)
    except Exception as e:
        log.critical(traceback.format_exc())
        raise Exception


def process_movies():
    try:
        return pynab.ids.process('movie', interfaces=config.postprocess.get('process_movies'),limit=500)
    except Exception as e:
        log.critical(traceback.format_exc())
        raise Exception


def process_nfos():
    try:
        return pynab.nfos.process(500)
    except Exception as e:
        log.critical(traceback.format_exc())
        raise Exception


def process_sfvs():
    try:
        return pynab.sfvs.process(500)
    except Exception as e:
        log.critical(traceback.format_exc())
        raise Exception


def process_rars():
    try:
        return pynab.rars.process(100)
    except Exception as e:
        log.critical(traceback.format_exc())
        raise Exception


def process_requests():
    try:
        return pynab.requests.process(500)
    except Exception as e:
        log.critical(traceback.format_exc())
        raise Exception


def main():
    log_init('postprocess')

    log.info('postprocess: starting post-processing...')

    # start with a quick post-process
    #log.info('postprocess: starting with a quick post-process to clear out the cruft that\'s available locally...')
    #scripts.quick_postprocess.local_postprocess()

    iterations = 0
    while True:
        with db_session() as db:
            # delete passworded releases first so we don't bother processing them
            if config.postprocess.get('delete_passworded', True):
                query = db.query(Release)
                if config.postprocess.get('delete_potentially_passworded', True):
                    query = query.filter((Release.passworded == 'MAYBE') | (Release.passworded == 'YES'))
                else:
                    query = query.filter(Release.passworded == 'YES')
                deleted = query.delete()
                db.commit()
                log.info('postprocess: deleted {} passworded releases'.format(deleted))

            with concurrent.futures.ThreadPoolExecutor(4) as executor:
                threads = []

                if config.postprocess.get('process_tvshows', True):
                    threads.append(executor.submit(process_tvshows))

                if config.postprocess.get('process_movies', True):
                    threads.append(executor.submit(process_movies))

                # grab and append nfo data to all releases
                if config.postprocess.get('process_nfos', True):
                    threads.append(executor.submit(process_nfos))

                # grab and append sfv data to all releases
                if config.postprocess.get('process_sfvs', False):
                    threads.append(executor.submit(process_sfvs))

                # check for passwords, file count and size
                if config.postprocess.get('process_rars', True):
                    threads.append(executor.submit(process_rars))

                # check for requests in local pre table
                if config.postprocess.get('process_requests', True):
                    threads.append(executor.submit(process_requests))

                #for t in concurrent.futures.as_completed(threads):
                #    data = t.result()

            # every 25 iterations (roughly), reset the unwanted status on releases
            """
            if iterations % 25 == 0:
                log.info('postprocess: resetting unwanted status')
                db.query(Release).filter(Release.unwanted==True).update({Release.unwanted: False})
                db.commit()
            """

            # rename misc->other and all ebooks
            scripts.rename_bad_releases.rename_bad_releases(8010)
            scripts.rename_bad_releases.rename_bad_releases(7020)

            # do a postproc deletion of any enabled blacklists
            # assuming it's enabled, of course
            if config.postprocess.get('delete_blacklisted_releases'):
                deleted = 0
                for blacklist in db.query(Blacklist).filter(Blacklist.status == True).all():
                    # remap subject to name, since normal blacklists operate on binaries
                    # this is on releases, and the attribute changes
                    field = 'search_name' if blacklist.field == 'subject' else blacklist.field

                    # filter by:
                    # group_name should match the blacklist's
                    #   <field> should match the blacklist's regex
                    #   <field> is determined by blacklist's field (usually subject/name)
                    #   date (optimisation)
                    query = db.query(Release).filter(Release.group_id.in_(
                        db.query(Group.id).filter(Group.name.op('~*')(blacklist.group_name)).subquery()
                    )).filter(getattr(Release, field).op('~*')(blacklist.regex))
                    if config.postprocess.get('delete_blacklisted_days'):
                        query = query.filter(Release.posted >= (datetime.datetime.now(pytz.utc) - datetime.timedelta(
                            days=config.postprocess.get('delete_blacklisted_days'))))
                    deleted += query.delete(False)
                log.info('postprocess: deleted {} blacklisted releases'.format(deleted))
                db.commit()

            if config.postprocess.get('delete_bad_releases', False):
                # kill unwanteds
                pass
                """
                deletes = db.query(Release).filter(Release.unwanted==True).delete()
                deletes = 0

                # and also kill other-miscs that we can't retrieve a rar for
                sub = db.query(Release.id).join(MetaBlack, Release.rar_metablack).\
                    filter(Release.category_id==8010).\
                    filter(MetaBlack.status=='IMPOSSIBLE').\
                    subquery()

                deletes += db.query(Release).filter(Release.id.in_(sub)).delete(synchronize_session='fetch')

                log.info('postprocess: deleted {} bad releases'.format(deletes))
                db.commit()
                """

            if config.postprocess.get('release_expiry_days', 0) > 0:
                expire_days = config.postprocess.get('release_expiry_days', 0)
                log.info('postprocess: expiring releases posted more than {} days ago.'.format(expire_days))
                deleted_releases = db.query(Release).filter(Release.posted < (datetime.datetime.now(pytz.utc) - datetime.timedelta(days=expire_days))).delete(synchronize_session='fetch')
                log.info('postprocess: expired {} releases'.format(deleted_releases))

            # delete any orphan metablacks
            log.info('postprocess: deleting orphan metablacks...')
            # noinspection PyComparisonWithNone,PyComparisonWithNone,PyComparisonWithNone,PyComparisonWithNone,PyComparisonWithNone
            deleted_metablacks = db.query(MetaBlack).filter(
                (MetaBlack.movie == None) &
                (MetaBlack.tvshow == None) &
                (MetaBlack.rar == None) &
                (MetaBlack.nfo == None) &
                (MetaBlack.sfv == None)
            ).delete(synchronize_session='fetch')
            log.info('postprocess: deleted {} orphaned metablacks.'.format(deleted_metablacks))

            # delete any orphan nzbs
            log.info('postprocess: deleting orphan nzbs...')
            # noinspection PyComparisonWithNone
            deleted_nzbs = db.query(NZB).filter(NZB.release == None).delete(synchronize_session='fetch')
            log.info('postprocess: deleted {} orphaned nzbs.'.format(deleted_nzbs))

            # delete any orphan nfos
            log.info('postprocess: deleting orphan nfos...')
            # noinspection PyComparisonWithNone
            deleted_nfos = db.query(NFO).filter(NFO.release == None).delete(synchronize_session='fetch')
            log.info('postprocess: deleted {} orphaned nfos.'.format(deleted_nfos))

            # delete any orphan sfvs
            log.info('postprocess: deleting orphan sfvs...')
            # noinspection PyComparisonWithNone
            deleted_sfvs = db.query(SFV).filter(SFV.release == None).delete(synchronize_session='fetch')
            log.info('postprocess: deleted {} orphaned sfvs.'.format(deleted_sfvs))

            db.commit()

            # vacuum the segments, parts and binaries tables
            log.info('postprocess: vacuuming relevant tables...')
            if iterations >= config.scan.get('full_vacuum_iterations', 288):
                # this may look weird, but we want to reset iterations even if full_vacuums are off
                # so it doesn't count to infinity
                if config.scan.get('full_vacuum', True):
                    vacuum(mode='postprocess', full=True)
                else:
                    vacuum(mode='postprocess', full=False)
                iterations = 0

        iterations += 1

        # wait for the configured amount of time between cycles
        postprocess_wait = config.postprocess.get('postprocess_wait', 300)
        log.info('sleeping for {:d} seconds...'.format(postprocess_wait))
        time.sleep(postprocess_wait)


if __name__ == '__main__':
    main()
