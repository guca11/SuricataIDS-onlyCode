Thresholding Keywords
=====================

Thresholding can be configured per rule and also globally, see
:doc:`../configuration/global-thresholds`.

Thresholds are tracked in a hash table that is sized according to configuration, see:
:ref:`suricata-yaml-thresholds`.

*Note: mixing rule and global thresholds is not supported in 1.3 and
before. See bug #425.* For the state of the support in 1.4 see
:ref:`global-thresholds-vs-rule-thresholds`

threshold
---------

The threshold keyword can be used to control the rule's alert
frequency. It has 3 modes: threshold, limit and both.

Syntax::

  threshold: type <threshold|limit|both|backoff>, track <by_src|by_dst|by_rule|by_both|by_flow>, count <N>, <seconds <T>|multiplier <M>>

type "threshold"
~~~~~~~~~~~~~~~~

This type can be used to set a minimum threshold for a rule before it
generates alerts. A threshold setting of N means on the Nth time the
rule matches an alert is generated.

Example::

  alert tcp !$HOME_NET any -> $HOME_NET 25 (msg:"ET POLICY Inbound Frequent Emails - Possible Spambot Inbound"; \
  flow:established; content:"mail from|3a|"; nocase;                                                       \
  threshold: type threshold, track by_src, count 10, seconds 60;                                           \
  reference:url,doc.emergingthreats.net/2002087; classtype:misc-activity; sid:2002087; rev:10;)

This signature only generates an alert if we get 10 inbound emails or
more from the same server in a time period of one minute.

If a signature sets a flowbit, flowint, etc. those actions are still
performed for each of the matches.

  *Rule actions drop (IPS mode) and reject are applied to each packet
  (not only the one that meets the threshold condition).*

type "limit"
~~~~~~~~~~~~

This type can be used to make sure you're not getting flooded with
alerts. If set to limit N, it alerts at most N times.

Example::

  alert http $HOME_NET any -> any $HTTP_PORTS (msg:"ET USER_AGENTS Internet Explorer 6 in use - Significant Security Risk"; \
  flow:to_server,established; content:"|0d 0a|User-Agent|3a| Mozilla/4.0 (compatible|3b| MSIE 6.0|3b|";                \
  threshold: type limit, track by_src, seconds 180, count 1;                                                           \
  reference:url,doc.emergingthreats.net/2010706; classtype:policy-violation; sid:2010706; rev:7;)

In this example at most 1 alert is generated per host within a period
of 3 minutes if MSIE 6.0 is detected.

If a signature sets a flowbit, flowint, etc. those actions are still
performed for each of the matches.

  *Rule actions drop (IPS mode) and reject are applied to each packet
  (not only the one that meets the limit condition).*

type "both"
~~~~~~~~~~~

This type is a combination of the "threshold" and "limit" types. It
applies both thresholding and limiting.

Example::

  alert tcp $HOME_NET 5060 -> $EXTERNAL_NET any (msg:"ET VOIP Multiple Unauthorized SIP Responses TCP"; \
  flow:established,from_server; content:"SIP/2.0 401 Unauthorized"; depth:24;                      \
  threshold: type both, track by_src, count 5, seconds 360;                                        \
  reference:url,doc.emergingthreats.net/2003194; classtype:attempted-dos; sid:2003194; rev:6;)

This alert will only generate an alert if within 6 minutes there have
been 5 or more "SIP/2.0 401 Unauthorized" responses, and it will alert
only once in that 6 minutes.

If a signature sets a flowbit, flowint, etc. those actions are still
performed for each of the matches.

  *Rule actions drop (IPS mode) and reject are applied to each packet.*

type "backoff"
~~~~~~~~~~~~~~

Allow limiting of alert output by using a backoff algorithm.

Syntax::

    threshold: type backoff, track by_flow, count <C>, multiplier <M>;

``track``: backoff is only supported for ``by_flow``
``count``: number of alerts before the first match is logged
``multiplier``: value to multiply ``count`` with each time the next value is reached

A count of 1 with a multiplier of 10 would generate alerts for matching packets::

    1, 10, 100, 1000, 10000, 100000, etc.

A count of 1 with a multiplier of 2 would generate alerts for matching packets::

    1, 2, 4, 8, 16, 32, 64, etc.

A count of 5 with multiplier 5 would generate alerts for matching packets::

    5, 25, 125, 625, 3125, 15625, etc

In the following example, the ``pkt_invalid_ack`` would only lead to alerts the 1st, 10th, 100th, etc.

.. container:: example-rule

    alert tcp any any -> any any (stream-event:pkt_invalid_ack; \
        :example-rule-options:`threshold:type backoff, track by_flow, count 1, multiplier 10;`
        sid:2210045; rev:2;)

If a signature sets a flowbit, flowint, etc. those actions are still
performed for each of the matches.

  *Rule actions drop (IPS mode) and reject are applied to each matching packet.*


track
~~~~~

.. table::

   +------------------+--------------------------+
   |Option            |Tracks By                 |
   +==================+==========================+
   |by_src            |source IP                 |
   +------------------+--------------------------+
   |by_dst            |destination IP            |
   +------------------+--------------------------+
   |by_both           |pair of src IP and dst IP |
   +------------------+--------------------------+
   |by_rule           |signature id              |
   +------------------+--------------------------+
   |by_flow           |flow                      |
   +------------------+--------------------------+


detection_filter
----------------

The detection_filter keyword can be used to alert on every match after
a threshold has been reached. It differs from the threshold with type
threshold in that it generates an alert for each rule match after the
initial threshold has been reached, where the latter will reset it's
internal counter and alert again when the threshold has been reached
again.

Syntax::

  detection_filter: track <by_src|by_dst|by_rule|by_both|by_flow>, count <N>, seconds <T>

Example::

  alert http $EXTERNAL_NET any -> $HOME_NET any \
       (msg:"ET WEB_SERVER WebResource.axd access without t (time) parameter - possible ASP padding-oracle exploit"; \
       flow:established,to_server; content:"GET"; http_method; content:"WebResource.axd"; http_uri; nocase;          \
       content:!"&t="; http_uri; nocase; content:!"&amp|3b|t="; http_uri; nocase;                                    \
       detection_filter:track by_src,count 15,seconds 2;                                                             \
       reference:url,netifera.com/research/; reference:url,www.microsoft.com/technet/security/advisory/2416728.mspx; \
       classtype:web-application-attack; sid:2011807; rev:5;)

Alerts each time after 15 or more matches have occurred within 2 seconds.

If a signature sets a flowbit, flowint, etc. those actions are still
performed for each of the matches.

  *Rule actions drop (IPS mode) and reject are applied to each packet
  that generate an alert*
