# Disable Accounts

Disable and re-enable accounts in WordPress multisite at will.

Allows disabling accounts without reassigning content or changing any other user details, preserving any content created by the users.


## Installation

Clone this repository into your plugins directory.


## Usage

Once the plugin has been network-enabled, access the Users screen in the Network Admin. You can then disable or re-enable individual accounts, or use the bulk actions to effect the changes.

Disabled accounts have the following effects applied:

* Their password will be reset to a random, unguessable 40 character password.
* Their existing login sessions will be reset, logging them out from all sites.
* They will be blocked from logging in with a message that their account is disabled.
* The account cannot perform any actions even if they do regain access (i.e. using third-party authentication plugins for access keys)

All other details of the accounts are preserved, and accounts can be reactivated. This includes per-site roles, so their access can easily be restored if desired. It also includes email addresses (preserving Gravatars), and in some cases, email messages will continue to be sent to their accounts. (Custom email code should check user capabilities before sending any potentially sensitive email.)


## Credits

Created by Human Made. Licensed under the GPLv2 or later.

Written and maintained by Ryan McCue.
