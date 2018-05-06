<?php

/*
 * SFSQuery: A PHP client to query the StopForumSpam API
 *
 * Copyright 2018 Shaun Cummiskey, <shaun@shaunc.com> <https://shaunc.com>
 * <https://github.com/parseword/sfsquery/>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//There may not be an autoloader available for this standalone example script
if (file_exists('vendor/autoload.php')) {
    @include 'vendor/autoload.php';
}
if (!class_exists('parseword\SFSQuery\SFSQuery')) {
    require_once 'src/SFSQuery.php';
}

//Explicitly import the class so we can use its short name
use parseword\SFSQuery\SFSQuery;

//Format output for console or web?
$break = (php_sapi_name() == 'cli') ? "\n" : '<br/>';

//Create a new SFSQuery object for a particular IP address. Normally,
//you'll want to pass $_SERVER['REMOTE_ADDR'] to the constructor here.
$sfs = new SFSQuery('5.135.189.186');

//Demonstrate accessing the StopForumSpam data for this IP address
echo "getApiResponse(): {$sfs->getApiResponse()} $break";
echo "getAppears(): {$sfs->getAppears()} $break";
echo "getAsn(): {$sfs->getAsn()} $break";
echo "getConfidence(): {$sfs->getConfidence()} $break";
echo "getCountry(): {$sfs->getCountry()} $break";
echo "getError(): {$sfs->getError()} $break";
echo "getFrequency(): {$sfs->getFrequency()} $break";
echo "getIp(): {$sfs->getIp()} $break";
echo "getLastSeen(): {$sfs->getLastSeen()} $break";

//Demonstrate protecting a resource based upon multiple criteria
if ($sfs->wasReportedInPastDays(7) && $sfs->getConfidence() >= 75) {
    echo "This user's comment would be rejected outright $break";
    //...display an error page here...
}
else if ($sfs->wasReportedInPastDays(30) && $sfs->getConfidence() >= 20) {
    echo "This user's comment would be flagged for moderator review $break";
    //...process the comment and notify a moderator to check it...
}
else {
    echo "This user's comment would be accepted $break";
    //...process the comment here...
}
