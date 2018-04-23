# SFSQuery

A PHP class to query the [StopForumSpam](https://stopforumspam.com/) API for 
information about an IP address. Help protect your comments, contact form, or 
other user-generated content from spammers by checking the StopForumSpam 
database in real time. 

### Usage

SFSQuery is platform-agnostic and can be used with any project. 
Simply `require()` the class file or place it where your autoloader can find it. 
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
    //Process the comment
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

* `getAsn()` - The Autonomous System Number that announces the IP, useful for 
blocking whole providers.

* `getConfidence()` - A score from 0 to 100 calculated by StopForumSpam 
indicating how likely the IP is to be a spammer. 

* `getCountry()` - Two-letter country code corresponding to the IP (reasonably 
accurate).

* `getFrequency()` - How many times the IP has been reported to StopForumSpam. 

* `getLastSeen()` - The epoch timestamp of the most recent time an IP was reported. 

There are several additional methods available:

* `getApiResponse()` - If a query succeeds, this will contain the JSON reply 
from StopForumSpam.

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

### Requirements

`SFSQuery` is written for PHP 7. To perform network connections, it requires 
*one* of the following to be available: fopen() URL wrappers, curl, or fsockopen()

### Limitations

At present, only queries for IP addresses are supported. Queries for email 
addresses may come in a future release. 
