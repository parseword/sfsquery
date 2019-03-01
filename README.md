# SFSQuery

A PHP class to query the [StopForumSpam](https://stopforumspam.com/) web API or DNSBL for 
information about an IP address. Help protect your comments, contact form, or 
other user-generated content from spammers by checking the StopForumSpam 
database in real time. 

### Usage

SFSQuery is platform-agnostic and can be used with any project. 
Simply `require()` the class file or place it where your autoloader can find it; 
Composer installation is supported.

The simplest implementation uses an anonymous object to check whether or not an 
IP meets one of several criteria. For example, you might want to reject an action 
if the user's IP has been reported to StopForumSpam in the past 7 days:

```php
<?php
use parseword\SFSQuery\SFSQuery;

if ((new SFSQuery($_SERVER['REMOTE_ADDR']))->wasReportedInPastDays(7)) {
    header('HTTP/1.1 403 Forbidden');
    echo "Sorry, you don't have access to this resource.";
    exit;
}
else {
    //Process the action
}
```

Because IP addresses frequently change hands, it's wise to use a more refined 
assessment based upon multiple factors. Just instantiate an `SFSQuery` object 
and call as many getter methods as you need. Let's check to see if an IP has 
been reported in the past 30 days, *and* has a spammer confidence level greater 
than 25%:

```php
<?php
use parseword\SFSQuery\SFSQuery;

$sfs = new SFSQuery($_SERVER['REMOTE_ADDR']);
if ($sfs->wasReportedInPastDays(30) && $sfs->getConfidence() > 25) {
    //Reject the comment
    exit;
}
else {
    //Process the comment
}
```
Perhaps you want to reject IPs from Russia which have been reported to 
StopForumSpam more than 10 times:

```php
<?php
use parseword\SFSQuery\SFSQuery;

$sfs = new SFSQuery($_SERVER['REMOTE_ADDR']);
if ($sfs->getFrequency() > 10 && $sfs->getCountry() == 'ru') {
    //Reject the comment
    exit;
}
else {
    //Process the comment
}
```
You should experiment to figure out what combination of factors is too "spammy" 
for your liking. You don't want to let a bunch of spammers through, but you 
don't want to cause a lot of false positives either. Consider a multi-tiered 
approach where high confidence spammers get rejected outright, lower scoring 
IPs have their comments flagged for moderator review, and totally clean IPs are 
free to submit content at will.

### Method overview

StopForumSpam offers several data points about each IP in their 
database. `SFSQuery` exposes them all through getter methods.

* `getAppears()` - Whether or not the IP is in the StopForumSpam database. 

* `getAsn()` - The Autonomous System Number that announces the IP. (Web API only.)

* `getConfidence()` - A score from 0 to 100 calculated by StopForumSpam 
indicating how likely the IP is to be a spammer. 

* `getCountry()` - Two-letter country code corresponding to the IP; reasonably 
accurate. (Web API only.)

* `getFrequency()` - How many times the IP has been reported to StopForumSpam. 

* `getLastSeen()` - The epoch timestamp of the most recent time an IP was reported. 

There are several additional methods available:

* `setQueryMethod()` - Switch from querying the web API (default) to the DNSBL, 
see next section.

* `getApiResponse()` - If an API query succeeds, this will contain the JSON reply 
from StopForumSpam.

* `getDnsResponse()` - If a DNSBL query succeeds, this will contain the A record 
or `NXDOMAIN`.

* `getError()` - If an error was encountered, this should tell you why.

* `wasReportedInLastDays()` - Whether or not the IP has been reported in the 
specified number of days.

* `wasReportedSince()` - Whether or not the IP has been reported since the 
given epoch timestamp.

To prevent unnecessary network traffic, the StopForumSpam API is queried only 
once during the lifetime of an `SFSQuery` object, with all of the data points 
being set during the initial query. If you use an object caching layer on top 
of PHP, consider forcing `SFSQuery` objects to be garbage collected at some 
regular interval so you aren't seeing stale results. 

### Querying the StopForumSpam DNSBL

`SFSQuery` version 1.1.0 introduces the ability to query StopForumSpam's DNSBL 
service instead of the web API. Using the DNSBL offers several advantages:

* Requests are smaller, decreasing network traffic
* DNS typically uses UDP, eliminating TCP setup/teardown time
* Responses are cached by the DNS infrastructure, reducing load on StopForumSpam

The trade-off is that StopForumSpam's DNSBL doesn't provide information about 
the target IP's ASN or country code. The `getAsn()` and `getCountry()` methods 
aren't compatible with DNSBL mode and will return 0 and null, respectively.

To make `SFSQuery` use the DNSBL instead of the web API, you *must* instantiate 
an SFSQuery object and call `setQueryMethod(SFSQuery::QUERYMETHOD_DNS);`

```php
<?php
use parseword\SFSQuery\SFSQuery;

$sfs = new SFSQuery($_SERVER['REMOTE_ADDR']);
$sfs->setQueryMethod(SFSQuery::QUERYMETHOD_DNS);

if ($sfs->wasReportedInPastDays(7) && $sfs->getConfidence() > 50) {
    //Reject the comment
    exit;
}
else {
    //Process the comment
}
```
Remember that if you use the DNSBL service, you won't be able to test for 
the IP's ASN or country code.

### Requirements

`SFSQuery` is written for PHP 7. To perform API connections, it requires 
*one* of the following to be available: `fopen()` URL wrappers, curl, or `fsockopen()`. 
To query the DNSBL, the `gethostbyname()` function must be available.

### Limitations

At present, only queries for IP addresses are supported. Web API queries can be 
made for both IPv4 and IPv6 addresses. DNSBL queries are currently limited to IPv4 
addresses only. The ability to query email addresses may come in a future release. 

### Disclaimer

The author is not affiliated with the StopForumSpam project. Any use of their 
service must comply with their [Acceptable Use Policy](https://www.stopforumspam.com/legal).
