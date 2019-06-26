# django-basicauthly
Basic Authentication support for Django

## Status

WIP - currently supporting a soft authentication middleware only. See below.

Lots of TODOs in motion to create more utils and options, as well as testing before publication.

## Notes

In order to work alongside other authentication schemes and middleware, this middleware only performs authentication checks and a login() when basic auth credentials have actually been passed to the request. Else it just passes the request on unhindered so that other middleware can decide what to do.
    
Should the Django session security module be installed it will keep it informed via set_last_activity.
    
Should the Django rest framework be installed, we also provide a simple replacement for it's SessionAuthentication class that prevents csrf check failures.
