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

namespace parseword\SFSQuery;

//TCP connect timeout (in seconds) to use
define('SFS_NET_TIMEOUT', 3);

//User-Agent string to present to the StopForumSpam API
define('SFS_USER_AGENT', 'SFSQuery/4 (+https://github.com/parseword/)');

//Components of the API URI. You should leave this alone unless you need to
//connect to a specific regional server.
define('SFS_API',
        ['proto' => 'http://', 'host' => 'api.stopforumspam.org', 'uri' => '/api?json&ip=']
);

class SFSQuery
{

    private $queried = false;
    private $ip = null;
    private $apiResponse = null;
    private $appears = false;
    private $confidence = 0.00;
    private $country = null;
    private $frequency = 0;
    private $lastSeen = 0;
    private $asn = 0;
    private $error = null;

    /**
     * Constructor. Pass the IPv4 or IPv6 address you want to query for.
     *
     * @param string $ip
     */
    public function __construct(string $ip) {
        $this->ip = $ip;
    }

    /**
     * Return the target IP address this object will query for.
     *
     * @return string
     */
    public function getIp() {
        return $this->ip;
    }

    /**
     * Test whether or not the target IP address is valid. Private (RFC1918) and
     * various reserved IPs (broadcast, multicast, etc.) will return false.
     *
     * @return bool
     */
    private function ipIsValid(): bool {
        return filter_var($this->getIp(), FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * Return the raw response received from the StopForumSpam API server.
     * In the case of a successful query, this will contain JSON. If a query
     * fails, this will return null; call getError() to see why.
     *
     * @return string or null
     */
    public function getApiResponse() {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->apiResponse;
    }

    /**
     * Set the apiResponse property.
     *
     * @param string $apiResponse
     */
    private function setApiResponse(string $apiResponse) {
        $this->apiResponse = $apiResponse;
    }

    /**
     * Return whether or not the target IP address appears in the StopForumSpam
     * database over any time period. This alone should not be used as the
     * basis for denying access, as reports may be several years old.
     *
     * @return bool
     */
    public function getAppears(): bool {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->appears;
    }

    /**
     * Set the appears property.
     *
     * @param bool $appears
     */
    private function setAppears(bool $appears) {
        $this->appears = $appears;
    }

    /**
     * Return the autonomous system number (ASN) corresponding to the target IP.
     *
     * @return int
     */
    public function getAsn(): int {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->asn;
    }

    /**
     * Set the asn property.
     *
     * @param int $asn
     */
    private function setAsn(int $asn) {
        $this->asn = $asn;
    }

    /**
     * Return the confidence score calculated by StopForumSpam. This value
     * represents the likelihood that the target IP is a spammer, based upon
     * the frecency of reports.
     *
     * @return float
     */
    public function getConfidence(): float {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->confidence;
    }

    /**
     * Set the confidence property.
     *
     * @param float $confidence
     */
    private function setConfidence(float $confidence) {
        $this->confidence = $confidence;
    }

    /**
     * Return a country code corresponding to the target IP, as determined by
     * StopForumSpam. Note that this value may be inaccurate as IPv4 space is
     * constantly being sold, SWIP'd, or otherwise reallocated.
     *
     * @return string or null
     */
    public function getCountry() {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->country;
    }

    /**
     * Set the country property.
     *
     * @param string $country
     */
    private function setCountry(string $country) {
        $this->country = $country;
    }

    /**
     * Return the error message, if an error has been encountered. If no known
     * error exists, returns null.
     *
     * @return string or null
     */
    public function getError() {
        return $this->error;
    }

    /**
     * Set the error property.
     *
     * @param string $error
     */
    private function setError(string $error) {
        $this->error = $error;
    }

    /**
     * Return the number of times the target IP has been reported to the
     * StopForumSpam database.
     *
     * @return int
     */
    public function getFrequency(): int {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->frequency;
    }

    /**
     * Set the frequency property.
     *
     * @param int $frequency
     */
    private function setFrequency(int $frequency) {
        $this->frequency = $frequency;
    }

    /**
     * Return the epoch timestamp corresponding to the target IP's most recent
     * report in the StopForumSpam database. For example, the epoch timestamp
     * for April 20, 2018 at 4:20 PM (GMT) is 1524241200.
     *
     * If no reports exist, this will return 0.
     *
     * @return int
     */
    public function getLastSeen(): int {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->lastSeen;
    }

    /**
     * Set the lastSeen property.
     *
     * @param int $lastSeen
     */
    private function setLastSeen(int $lastSeen) {
        $this->lastSeen = $lastSeen;
    }

    /**
     * Query the StopForumSpam API server for information about the target IP.
     * For portability, three different request methods are available: fopen
     * wrappers, curl, and sockets.
     *
     * If the query is successful, the various object properties are populated,
     * and the raw JSON response can be retrieved with getApiResponse(). If
     * something fails, getApiResponse() will return null and getError() will
     * explain what happened.
     *
     * Returns true on success, false on failure.
     *
     * @return bool
     */
    public function apiQuery(): bool {

        //To avoid spurious traffic, bail if we've already sent a request
        if ($this->queried) {
            return true;
        }

        //Don't query for unsupported IP addresses
        if (!$this->ipIsValid()) {
            $this->setError('Private, reserved, or invalid IP address');
            return false;
        }

        $response = null;

        //Use file_get_contents if it's available
        if (ini_get('allow_url_fopen')) {
            ini_set('user_agent', SFS_USER_AGENT);
            if (!$response = @file_get_contents(join(SFS_API) . $this->getIp())) {
                $this->setError(error_get_last()['message']);
                return false;
            }
        }

        //Otherwise use curl if it's available
        else if (function_exists('curl_init')) {
            $ch = curl_init(join(SFS_API) . $this->getIp());
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, SFS_NET_TIMEOUT);
            curl_setopt($ch, CURLOPT_TIMEOUT, SFS_NET_TIMEOUT);
            curl_setopt($ch, CURLOPT_USERAGENT, SFS_USER_AGENT);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            if (!$response = @curl_exec($ch)) {
                $this->setError(curl_error($ch));
                return false;
            }
            curl_close($ch);
        }

        //As a last resort, try to do the request manually (plain HTTP only)
        else if (function_exists('fsockopen') && (strpos(SFS_API['proto'], 's') === false)) {
            ini_set('default_socket_timeout', SFS_NET_TIMEOUT);
            if ($sock = @fsockopen(SFS_API['host'], 80)) {
                $request = 'GET ' . SFS_API['uri'] . $this->ip . " HTTP/1.0\r\n"
                        . 'Host: ' . SFS_API['host'] . "\r\n"
                        . 'User-Agent: ' . SFS_USER_AGENT . "\r\n"
                        . "Accept: text/txt,text/html;q=0.9,*/*;q=0.8\r\n"
                        . "Connection: close\r\n\r\n";
                fwrite($sock, $request);
                while (!feof($sock)) {
                    $response .= fread($sock, 10240);
                }
                //Disregard the HTTP headers
                list (, $response) = explode("\r\n\r\n", $response);
            }
            else {
                $this->setError(error_get_last()['message']);
                return false;
            }
        }
        else {
            $this->setError('No supported connection method was found');
            return false;
        }

        //Flag that we've been here
        $this->queried = true;

        //Cache the response
        $this->setApiResponse(trim($response));

        //Decode the JSON response
        if (!$answer = json_decode($response, true)) {
            $this->setError('Server response could not be decoded from JSON');
            return false;
        }

        //Bail if the query failed
        if (empty($answer['success'])) {
            $this->setError('Server response indicated query failure');
            return false;
        }

        //Populate variables from the results
        if (!empty($answer['ip']['lastseen'])) {
            $this->setLastSeen(strtotime($answer['ip']['lastseen'] . ' GMT'));
        }

        if (!empty($answer['ip']['frequency']) && is_numeric($answer['ip']['frequency'])) {
            $this->setFrequency($answer['ip']['frequency']);
        }

        if (!empty($answer['ip']['appears'])) {
            $this->setAppears(true);
        }

        if (!empty($answer['ip']['confidence']) && is_numeric($answer['ip']['confidence'])) {
            $this->setConfidence($answer['ip']['confidence']);
        }

        if (!empty($answer['ip']['country'])) {
            $this->setCountry($answer['ip']['country']);
        }

        if (!empty($answer['ip']['asn']) && is_numeric($answer['ip']['asn'])) {
            $this->setAsn($answer['ip']['asn']);
        }

        return true;
    }

    /**
     * Return whether or not the target IP has been reported since a given
     * unix epoch timestamp. For example, to see if there were any reports in
     * the past 12 hours, use wasReportedSince(time() - 7200)
     *
     * @param int $epoch
     * @return bool
     */
    public function wasReportedSince(int $epoch): bool {
        if (!$this->queried) {
            $this->apiQuery();
        }
        return $this->appears && $this->lastSeen > $epoch;
    }

    /**
     * Return whether or not the target IP has been reported in the past $days
     * days. For example, to see if there were any reports in the past 90 days,
     * use wasReportedInPastDays(90). If no value is passed, the default is
     * to test for the last 7 days.
     *
     * @param int $days
     * @return bool
     */
    public function wasReportedInPastDays(int $days = 7): bool {
        return $this->wasReportedSince(time() - (86400 * $days));
    }

}
