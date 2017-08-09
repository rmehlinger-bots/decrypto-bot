#!/usr/bin/env python3
# Original by @Roguelazer:
# https://gist.githubusercontent.com/Roguelazer/51852b46a6a3ff62e8a2eab813c74fc2/raw/8d14ed445665c5ded676e901bb2f90c42acf0276/richard_bot.py

import argparse
import base64
import json
import re
import sqlite3

from github import Github


BAD_REGEXP = re.compile(r'"crypto":\s*"0.0.3"')

MORE_INFO_URL = '/path/to/blog/post'


def chunk(i, sz):
    c = []
    for item in i:
        c.append(item)
        if len(c) == sz:
            yield c
            c = []
    if c:
        yield c


def create_issues(db, created, g, args):
    c = db.cursor()
    c.execute('SELECT repository, group_concat(filename) AS files FROM findings WHERE issue_number IS NULL GROUP BY repository')
    for row in c:
        repo = g.get_repo(row['repository'])
        issue_kwargs = {
            'title': 'Insecure use of crypto==0.0.3',
            'body': ''''This automated scanner has detected the use of the crypto library version
0.0.3 in the following files:

%s

Please see %s for more details''' % (row['files'], MORE_INFO_URL),
        }
        if args.pretend:
            print('Would create the following issue on %s' % repo.full_name)
            print(json.dumps(issue_kwargs))
        else:
            issue = repo.create_issue(**issue_kwargs)
            created[repo.full_name] = issue.id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--github-token', required=True,
        help='Access token from https://github.com/settings/tokens'
    )
    parser.add_argument(
        '-f', '--findings-file', required=True,
        help='Path to a file where we will store intermediate findings'
    )
    parser.add_argument(
        '--skip-search', action='store_true',
        help=(
            'Skip running the search and just file tickets '
            'based on the contents of -f'
        )
    )
    parser.add_argument('-p', '--pretend', action='store_true',
                        help='Do not really create issues')
    args = parser.parse_args()

    g = Github(login_or_token=args.github_token)
    status = g.get_api_status()
    if status.status != 'good':
        raise ValueError('Unable to reach github: {0!r}'.format(status))

    db = sqlite3.connect(args.findings_file)
    db.row_factory = sqlite3.Row

    db.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            repository TEXT NOT NULL,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            issue_number INT DEFAULT NULL
        )
    ''')
    db.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS
            findings_repository_filename
        ON findings(repository, filename)
    ''')

    db.execute('PRAGMA journal_mode=WAL')

    if not args.skip_search:
        for result_chunk in chunk(g.search_code('filename:package.json crypto 0.0.3'), 10):
            with db:
                for result in result_chunk:
                    content = base64.b64decode(result.content).decode('utf-8')
                    if BAD_REGEXP.search(content):
                        try:
                            db.execute('''
                                INSERT INTO findings(repository, filename, content)
                                VALUES(?, ?, ?)
                            ''', (result.repository.full_name, result.path, content))
                        except sqlite3.IntegrityError:
                            continue

    created = {}

    try:
        create_issues(db, created, g, args)
    finally:
        with db:
            for repo_name, issue_number in created.items():
                db.execute('UPDATE findings SET issue_number=? WHERE repository=?', (issue_number, repo_name))


main()
