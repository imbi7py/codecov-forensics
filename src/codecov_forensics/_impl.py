from automat import MethodicalMachine
import argparse
from gidgethub.treq import GitHubAPI
from hyperlink import URL
from lxml import etree, html
import treq
from twisted.internet import defer, task
from twisted.protocols import basic
from secretly import secretly
import sys


USER_AGENT = "codecode-forensics"


async def tipOfBranch(reactor, token, pullRequestNumber):
    api = GitHubAPI(USER_AGENT, oauth_token=token)
    response = await api.getitem("/repos/twisted/twisted/pulls/{number}",
                                 url_vars={"number": pullRequestNumber})
    return response['head']['sha']


async def anchorToPath(treq, url, anchor):
    response = await treq.get(url, headers={'user-agent': USER_AGENT})
    if response.code != 200:
        raise ValueError("Response failed", response.code)
    document = html.fromstring(await response.content())
    els = document.xpath(
        './/*[@data-anchor="{}" and @data-path]/@data-path'.format(anchor))
    if len(els) != 1:
        raise ValueError("Not exactly 1 anchor", len(els))
    return els[0]


async def buildsWithFileAndLine(treq, owner, repo, commit, path, line):
    url = f"https://codecov.io/gh/{owner}/{repo}/commit/{commit}/build"
    response = await treq.get(url, headers={'user-agent': USER_AGENT})
    if response.code != 200:
        raise ValueError("Response failed", response.code)
    codecovBuildsPage = await response.content()
    document = html.fromstring(codecovBuildsPage)
    cards = document.xpath(
        './/*[contains(@class, "ui")'
        ' and contains(@class, "color")'
        ' and contains(@class, "card")]')
    if not cards:
        raise ValueError("No UI cards")
    reportLinks = [
        link
        for card in cards
        for link in card.xpath('.//a[contains(text(), "Download")]/@href')
    ]
    reportsWithHits = await defer.gatherResults(
        [
            defer.ensureDeferred(findHits(treq, link, path, line))
            for link in reportLinks
        ]
    )
    return [
        extractDescription(cards[i])
        for i, hasHit in enumerate(reportsWithHits)
        if hasHit
    ]


class ParseCoverageXML(basic.LineOnlyReceiver):
    _fileParsingMachine = MethodicalMachine()
    delimiter = b'\n'

    def __init__(self, path, line, doneDeferred):
        self._path = path
        self._line = line
        self._doneDeferred = doneDeferred
        self._delete = True
        self._hasLine = False

    @_fileParsingMachine.state(initial=True)
    def _expectNetworkLine(self):
        pass

    @_fileParsingMachine.state()
    def _expectPathLine(self):
        pass

    @_fileParsingMachine.state()
    def _expectXML(self):
        pass

    @_fileParsingMachine.state()
    def _done(self):
        pass

    @_fileParsingMachine.input()
    def _receivedNetworkLine(self):
        pass

    @_fileParsingMachine.input()
    def _receivedPathLine(self):
        pass

    @_fileParsingMachine.input()
    def _receivedLine(self, line):
        pass

    @_fileParsingMachine.input()
    def _receivedEOF(self):
        pass

    @_fileParsingMachine.output()
    def _constructParser(self):
        self._parser = etree.XMLPullParser(events=("start", "end"))

    @_fileParsingMachine.output()
    def _parseXML(self, line):
        self._parser.feed(line)
        for event, element in self._parser.read_events():
            if element.tag == "class":
                if event == "start":
                    self._delete = False
                else:
                    self._delete = True
                    self._maybeCheckClass(element)
            if self._delete:
                element.clear()

    @_fileParsingMachine.output()
    def _close(self):
        self._parser.close()

    _expectNetworkLine.upon(
        _receivedLine, enter=_expectNetworkLine, outputs=[])
    _expectNetworkLine.upon(
        _receivedNetworkLine, enter=_expectPathLine, outputs=[])
    _expectPathLine.upon(
        _receivedLine, enter=_expectPathLine, outputs=[])
    _expectPathLine.upon(
        _receivedPathLine, enter=_expectXML, outputs=[_constructParser])
    _expectXML.upon(
        _receivedLine, enter=_expectXML, outputs=[_parseXML])
    _expectXML.upon(
        _receivedEOF, enter=_done, outputs=[_close])

    def _maybeCheckClass(self, element):
        if element.tag != "class" or element.get("filename") != self._path:
            return
        lines = element.xpath('lines/line')
        for line in lines:
            if line.get('number') == self._line and line.get('hits') != '0':
                self._hasLine = True
                return

    def lineReceived(self, line):
        if line == b"<<<<<< network":
            self._receivedNetworkLine()
        elif line == b"# path=coverage.xml":
            self._receivedPathLine()
        elif line == b"<<<<<< EOF":
            self._receivedEOF()
        else:
            self._receivedLine(line)

    def connectionLost(self, reason):
        self._doneDeferred.callback(self._hasLine)


async def findHits(treq, link, path, line):
    response = await treq.get(link)
    if response.code != 200:
        raise ValueError("Response failed", response.code)
    done = defer.Deferred()
    parser = ParseCoverageXML(path, line, done)
    response.deliverBody(parser)
    return (await done)


def extractDescription(cardElement):
    maybeDescripton = "".join(cardElement.xpath(
        ".//div[contains(@class, 'description')]//text()")).strip()
    if maybeDescripton:
        return maybeDescripton
    maybeLink = cardElement.xpath(
        './/a[contains(text(), "View CI Build")]/@href')
    if maybeLink:
        return maybeLink[0]
    return ''.join(cardElement.xpath(
        './/div[contains(@class, "header")]/text()')).strip()


async def printBuilds(reactor, url):
    parsed = URL.fromText(url)
    anchor, line = parsed.fragment.rsplit('R', 1)
    owner, repo = parsed.path[:2]
    pullRequestNumber = parsed.path[-2]

    githubToken = await secretly(
        reactor,
        action=lambda token: token,
        system="codecov-forensics-github",
    )

    tip = await tipOfBranch(reactor, githubToken, pullRequestNumber)
    path = await anchorToPath(treq, url, anchor)
    builds = await buildsWithFileAndLine(treq, owner, repo, tip, path, line)
    for build in builds:
        print(build)


@task.react
def main(reactor):
    url = sys.argv[1]
    return defer.ensureDeferred(printBuilds(reactor, url))
