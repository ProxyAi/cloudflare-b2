//
// Bot detection
//
// Source of list of bots from https://www.knthost.com/nginx/blocking-bots-with-nginx
//

// Bot detection regexes converted from Nginx rules
const SEARCH_BOTS = [
    /360spider/i,
    /Aboundex\/0\.3/i,
    /Applebot\/0\.1/i,
    /Baiduspider\/2\.0/i,
    /BigBozz\/2\.2\.1/i,
    /bingbot\/2\.0/i,
    /BingPreview\/1\.0b/i,
    /Cliqzbot\/1\.0/i,
    /coccocbot-image\/1\.0/i,
    /coccocbot-web\/1\.0/i,
    /Daumoa 4\.0/i,
    /DeuSu/i,
    /DoCoMo\/2\.0/i,
    /DuckDuckGo-Favicons-Bot\/1\.0/i,
    /EasouSpider/i,
    /Exploratodo\/1\.0/i,
    /FatBot/i,
    /Feedfetcher-Google/i,
    /FemtosearchBot/i,
    /Findxbot\/1\.0/i,
    /German Wikipedia Broken Weblinks Bot/i,
    /GigablastOpenSource\/1\.0/i,
    /Gigabot/i,
    /gimme60bot/i,
    /GimmeUSAbot\/1\.0/i,
    /Googlebot-Image\/1\.0/i,
    /Googlebot-Mobile\/2\.1/i,
    /Googlebot\/2\.1/i,
    /HaosouSpider/i,
    /Linguee Bot/i,
    /LpLinkCheck\/Nutch-1\.12/i,
    /Mail\.RU_Bot/i,
    /Mediapartners-Google/i,
    /Metaspinner\/1\.0/i,
    /MojeekBot/i,
    /msnbot-media/i,
    /msnbot-UDiscovery/i,
    /msnbot/i,
    /NerdyBot/i,
    /ODP/i,
    /OpenfosBot/i,
    /Plukkie\/1\.6/i,
    /psbot/i,
    /Qwantify/i,
    /SafeSearch microdata crawler/i,
    /search\.daum/i,
    /Seeker v\.1/i,
    /SemanticScholarBot/i,
    /SeznamBot\/3\.2/i,
    /Slurp/i,
    /SocialSearcher/i,
    /Sogou/i,
    /Sufog\/Nutch-2\.2\.1/i,
    /TinEye-bot\/0\.51/i,
    /vebidoobot/i,
    /WBSearchBot\/1\.1/i,
    /WbSrch\/1\.1/i,
    /Wotbox/i,
    /Y!J-ASR\/0\.1 crawler/i,
    /YandexBot\/3\.0/i,
    /YandexMobileBot\/3\.0/i,
    /yellowpages\.com/i,
    /Yeti\/1\.1/i,
    /YisouSpider/i,
    /yoozBot-2\.2/i,
    /ZumBot/i
];

const SOCIAL_BOTS = [
    /facebookexternalhit/i,
    /LinkedInBot/i,
    /Pinterest/i,
    /SkypeUriPreview/i,
    /Twitterbot/i,
    /WhatsApp/i
];

const DATA_COLLECTORS = [
    /007ac9/i,
    /008/i,
    /200PleaseBot/i,
    /A6-Indexer/i,
    /activesearchresults\.com/i,
    /adbeat_bot/i,
    /AddThis\.com/i,
    /ADmantX/i,
    /AhrefsBot/i,
    /aiHitBot/i,
    /AlphaBot/i,
    /archive\.org_bot/i,
    /Attentio\/Nutch/i,
    /BacklinkCrawler/i,
    /BiggerBetter/i,
    /BIXOCRAWLER/i,
    /Blackboard Safeassign/i,
    /BLEXBot/i,
    /BPImageWalker/i,
    /Barkrowler\/0\.7/i,
    /BDCbot\/1\.0/i,
    /Brodie\/1\.0/i,
    /BUbiNG/i,
    /Buck\/2\.2/i,
    /BusinessSeek\.biz_Spider/i,
    /Buzzbot\/1\.0/i,
    /BuzzSumo/i,
    /calculon spider/i,
    /CareerBot/i,
    /CATExplorador/i,
    /CCBot/i,
    /CheckMarkNetwork/i,
    /changedetection\.com/i,
    /CipaCrawler/i,
    /CityGridMedia\/1\.0/i,
    /Clickagy Intelligence Bot v2/i,
    /CloudServerMarketSpider/i,
    /CMS Crawler/i,
    /cmscrawler/i,
    /cognitiveseo/i,
    /collection@infegy\.com/i,
    /CommonCrawler Node/i,
    /Companybook-Crawler/i,
    /ContextAd Bot/i,
    /Contacts Crawler/i,
    /CoPubbot/i,
    /Corax/i,
    /crawler@fast\.no/i,
    /Crawlera\//i,
    /CRAZYWEBCRAWLER/i,
    /CSS Certificate Spider/i,
    /CybEye/i,
];

const SCANNERS = [
    /Comodo-Webinspector-Crawler/i,
    /ErrataSecScanner/i,
    /httpscheck/i,
    /Load Impact/i,
    /ltx71/i,
    /masscan/i,
    /mfibot\/1\.1/i,
    /muhstik-scan/i,
    /nikto/i,
    /Nmap Scripting Engine/i,
    /Nmap/i,
    /NYU Internet Census/i,
    /OpenVAS/i,
    /project25499\.com/i,
    /proxytest\.zmap\.io/i,
    /Researchscan\/t12sns/i,
    /Riddler/i,
    /SafeSearch microdata crawler/i,
    /ScanAlert/i,
    /scan\.nextcloud\.com/i,
    /Scanning for research/i,
    /SiteLock/i,
    /SiteLockSpider/i,
    /SSL Labs/i,
    /sysscan/i,
    /sqlmap/i,
    /zgrab\/0\.x/i
];

const DEV_TOOLS = [
    /aiohttp/i,
    /AppEngine-Google/i,
    /Apache-HttpClient/i,
    /Camo Asset Proxy/i,
    /Commons-HttpClient/i,
    /crawler4j/i,
    /curl/i,
    /Curl\/PHP 5\.5\.9-1ubuntu4\.13/i,
    /eContext\/1\.0/i,
    /EmbeddedWB/i,
    /fasthttp/i,
    /gocrawl/i,
    /Go http package/i,
    /Go 1\.1 package http/i,
    /Go-http-client/i,
    /Google-HTTP-Java-Client/i,
    /GuzzleHttp/i,
    /HeadlessChrome/i,
    /HEADMasterSEO/i,
    /httpbin\.org/i,
    /HTTP_Request2/i,
    /HttpUrlConnection/i,
    /Java/i,
    /Jersey/i,
    /libwww-perl/i,
    /lua-resty-http/i,
    /LWP::Simple/i,
    /MATLAB R2013a/i,
    /Mechanize\/2\.7\.2/i,
    /MetaInspector/i,
    /MetaURI/i,
    /Mojolicious \(Perl\)/i,
    /nghttp2/i,
    /nutch/i,
    /Pcore-HTTP/i,
    /PHPCrawl/i,
    /PSv3 \(SSL Connection\)/i,
    /PycURL/i,
    /python/i,
    /Python-urllib/i,
    /Ruby/i,
    /Scrapy/i,
    /scrapy-redis/i,
    /siege/i,
    /SiteCrawler/i,
    /Symfony BrowserKit/i,
    /synapse/i,
    /UniversalFeedParser/i,
    /wget/i,
    /WinHttp/i,
    /WWW-Mechanize/i,
    /Xenu Link Sleuth/i,
    /XML-RPC\.NET/i,
    /zgrab\/0\.x/i,
    /ZoomSpider/i
];

const BLOCKED_BOTS = [
    /Auto Spider 1\.0/i,
    /Babya Discoverer/i,
    /Crawlera/i,
    /Crowsnest\/0\.5/i,
    /DataCha0s/i,
    /DomainSONOCrawler\/0\.1/i,
    /Dow Jones Searchbot/i,
    /DownloadBot/i,
    /heritrix/i,
    /heritrix\/3\.1\.1/i,
    /JCE/i,
    /Morfeus f scanner/i,
    /Mozilla\/0\.6 Beta \(Windows\)/i,
    /Mozilla-1\.1/i,
    /MSProxy\/2\.0/i,
    /null/i,
    /proxyjudge\.info/i,
    /proxyjudge/i,
    /SecurityResearch\.bot/i,
    /SiteChecker\/0\.1/i,
    /WBSearchBot\/1\.1/i,
    /WebFuck/i,
    /Windows Live Writer/i,
    /WinHttp\.WinHttpRequest\.5/i,
    /ZmEu/i,
    /Zollard/i
];

const MONITORING_BOTS = [
    /checks\.panopta\.com/i,
    /HetrixTools Uptime Monitoring Bot/i,
    /InternetSeer\.com/i,
    /jetmon\/1\.0/i,
    /montastic-monitor/i,
    /nagios-plugins/i,
    /notifyninja\.com/i,
    /Pingdom\.com_bot_version_1\.4/i,
    /SiteChecker/i,
    /Sitemeer/i,
    /siteuptime/i,
    /Status Cake/i,
    /Uptimebot\/1\.0/i,
    /UptimeRobot\/2\.0/i,
    /Uptime\.com/i
];

/**
 * Checks if a user agent matches any pattern in the provided array.
 */
function matchesPattern(userAgent, patterns) {
    return patterns.some(pattern => pattern.test(userAgent));
}

/**
 * Determines if the user agent is a known bot.
 */
function isBot(userAgent) {
    if (!userAgent) return false;
    
    return matchesPattern(userAgent, SEARCH_BOTS) ||
           matchesPattern(userAgent, SOCIAL_BOTS) ||
           matchesPattern(userAgent, DATA_COLLECTORS) ||
           matchesPattern(userAgent, SCANNERS) ||
           matchesPattern(userAgent, DEV_TOOLS) ||
           matchesPattern(userAgent, BLOCKED_BOTS) ||
           matchesPattern(userAgent, MONITORING_BOTS);
}

/**
 * Gets the specific type of bot (for logging/monitoring purposes).
 */
function getBotType(userAgent) {
    if (!userAgent) return 'unknown';
    
    if (matchesPattern(userAgent, BLOCKED_BOTS)) return 'blocked';
    if (matchesPattern(userAgent, SCANNERS)) return 'scanner';
    if (matchesPattern(userAgent, SEARCH_BOTS)) return 'search';
    if (matchesPattern(userAgent, SOCIAL_BOTS)) return 'social';
    if (matchesPattern(userAgent, DATA_COLLECTORS)) return 'collector';
    if (matchesPattern(userAgent, DEV_TOOLS)) return 'devtool';
    if (matchesPattern(userAgent, MONITORING_BOTS)) return 'monitoring';
    
    return 'unknown';
}

/**
 * Handles the response for blocked requests.
 */
function getBlockedResponse(botType) {
    const headers = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block'
    };

    if (botType === 'blocked' || botType === 'scanner') {
        return new Response("Forbidden", { status: 403, headers });
    }

    return new Response("Not Found", { status: 404, headers });
}

export { isBot, getBotType, getBlockedResponse };
