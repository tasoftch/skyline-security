# Skyline Security
The Skyline Security Package provides several services to increase your application's security.

Skyline Security adds the security service to use in your action controllers.
## Install
Manual created applications do not install the security package automatically.  
You can easy add them using composer:
```php
$ composer require skyline/security
```
## How it works
The Skyline Security package has two functions:
1. Manage access control to your application
1. Protect html forms against cross site request forgery

### Manage Access
Skyline Security uses three phases for access control

##### Phase 1: Identification
Who is requesting?  
There are several possibilities to detect the identity of a requesting client:
- Anonymous: You don't know who it is, but the identity is always the same
- Remember Me: An identity created from remember me information
- Session: An identity for the current session
- HTTP: Basic and Digest identities specified by HTTP/1.0
- HTML Form Login
- API Keys

All identities must specify a token (usually a username, but can be anything). This identifies a client.  
Identities also specify a reliability.


##### Phase 2: Authentication
Does Skyline CMS know someone with this token (username)?  
For this Skyline Security needs user providers that know registered users by token.  
If Skyline knows a user with a given identity, it tries to authenticate the identity using its credentials.  
Now the credentials are wrong, the authentication phase will break and send an authentication challenge to the client.  
But if the credentials matched, phase 3 takes place

##### Phase 3: Authorization
Is the user allowed to perform the desired action?  
Skyline Security knows voters to decide, if the request is granted or denied.  
The package ships with a role system.  
You as administrator can assign as many roles as you want to users.  
After that, every action in an action controller can require roles. So now Skyline Security only grant access to the desired action if the user has all required roles.


### Cross Site Request Forgery

```php
$csrfManager = ServiceManager::generalServiceManager()->CSRFManager;
```

#### Special Thanks To
- Symfony ( Copyright (c) 2004-2019 Fabien Potencier )