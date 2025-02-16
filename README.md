# cro-http-session-sqlite
Cro::HTTP::Session::SQLite

# NAME

Cro::HTTP::Session::SQLite - An implementation of Cro persistent sessions using SQLite.

# SYNOPSIS

```raku
use Cro::HTTP::Session::SQLite;
```

# DESCRIPTION

There are dozens of ways we might do session storage; this module handles the case where:

- The database is being accessed using DBIish.
- You're fine with the session state being serialized and stored as a JSON in the database.

If these don't meet your needs, it's best to steal the code from this module into your own application and edit it as needed.

# INSTALLATION

```raku
zef install Cro::HTTP::Session::SQLite
```

# FUNCTIONALITY

- Store the session data in local SQLite3 file

- Auto create the db file and table if missing

- Using your own SQLite DBIish connection if required

- Encrypted data store using OpenSSL::CryptTools AES256

- Session auto cleanup or on every request

- Configurable table name and columns

- Store the user ID and IP address from the session

- Skip creating a session

- JSON state storage in a json type column

- Base64 state storage when encrypted

- IP cookie binding


# Database default setup

- The table name can be changed

- Every column is configurable

- The table will be created if missing

```sql
CREATE TABLE IF NOT EXISTS sessions (
	id varchar(255), 
	state json,
	ip_addr varchar(255),
	user_id INTEGER,
	expiration TIMESTAMP,
	created TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
);
CREATE INDEX session_id ON sessions (id);
CREATE INDEX expired_date ON sessions (expiration);
```

# Minimal Cro application setup


```raku
class MySession {
    has $.user-id;
	has $.ip-addr;

    method set-logged-in-user($!user-id --> Nil) { }
    method is-logged-in(--> Bool) { $!user-id.defined }
}

my $application = route {

    before Cro::HTTP::Session::SQLite[UserSession].new();

    get -> UserSession $user {
        $user.user-id = 123;
		$user.ip-addr = '127.0.0.1';
        content 'text/plain', "Hello, TEST!";
    }
}

my Cro::Service $hello = Cro::HTTP::Server.new:
    :host<localhost>, :port(80), :$application;
```

Here are the keypoints here:
- Creates a ./sessions.db file

- Cookie expiration time is 30 min

- Auto clean the sessions table every 30 min

- Prevent session loading if the user IP address doesn't match the stored one

# Custom setup

```raku
before Cro::HTTP::Session::SQLite[UserSession].new( 
	expiration => Duration.new(60 * 60), # 60 minutes expiration
	cookie-name => 'CustomCookieName',
	db-path => '/home/user/app/sessions.db',
	restrict-ip-addr => True,
	autoclean-every-seconds => 60, # Cleanup the sessions table every 60 seconds
	key => ("0" x 32).encode, - Encryption key
	iv => ("0" x 16).encode, - Encryption IV
	skip-cookie => -> Cro::HTTP::Response $response { # Skip the cookie if the request is application/json
		my $content-type = $response.request.header('content-type');
		$content-type && $content-type eq 'application/json'
		}
	);
```

Here we have a custom setup:

- Expiration time is **60 minutes**

- Cookie name is **CustomCookieName**

- SQLite DB file is **/home/user/app/sessions.db**

- Cookie is restricted only to the IP address previously stored

- Expired sessions are deleted from the DB every 60 seconds

- The data is encrypted using a default KEY and IV and you **must CHANGE IT**

- Cookie is ignored if the request content type is application/json

For full setup see the constructor below

# Constructor

All fields are optional

> DBDish::SQLite::Connection $.db
DBIish connection. **Default** auto connects

> IO::Path $.db-path
Path to the DB SQLite3 file. **Default** `./sessions.db`

> Str $.cookie-name
Name of the cookie. **Default** CroCookie

> Duration $.expiration
Expiration duration for the cookie. **Default** `Duration.new( 30*60 )`

> Int $.autoclean-every-seconds
Session cleanup every X seconds. **Default** 1800

* -1 Disable session removal
* 0 Delete the expired sessions on every request
* 1+ Delete the expired sessions every X seconds

> Str $.sessions-table
Name of the DB table. **Default** sessions

> Str $.id-column
Name of the ID column in the DB. **Default** id

> Str $.state-column
Name of the state column in the DB. **Default** state

> Str $.expiration-column
Name Of the expiration column. **Default** expiration

> Str $.ip-addr-column
Name of the IP address column. **Default** ip_addr

> Str $.user-id-column
Name of the User ID column. **Default** user_id

> Str $.created-column
Name of the Created column. **Default** created

> Str $.ip-addr-field
Field name from your Session object, that is used to store the IP address in the table column $.ip-addr-column. **Default** ip-addr

-2 Nil to disable storing the IP address

> Str $.user-id-field
Field name from your Session object, that is used to store the User ID in the table column $.user-id-column. **Default** user-id

-2 Nil to disable storing the User ID

> Bool $.restrict-ip-addr
IP cookie bind. Looksup the $.ip-addr-field from your Session object. **Default** *True*

> Callable &.skip-cookie
Custom function that can disable the session. **Default** *Nil*

> Buf() $.key
Encryption key. See L<OpenSSL|https://raku.land/github:sergot/OpenSSL#opensslcrypttools> for more information

> Buf() $.iv
IV. See L<OpenSSL|https://raku.land/github:sergot/OpenSSL#opensslcrypttools> for more information

# Controlling serialized data

Instead of using the Cro::HTTP::Session::SQLite role directly, create a class that composes it.

=begin code :lang<raku>
class MySessionStore does Cro::HTTP::Session::SQLite[MySession] {
    method serialize(MySession $s --> Hash) {
        # Replace this with your serialization logic.
        $s.Capture.hash
    }
    
    method deserialize(Str $d --> MySession) {
        # Replace this with your deserialization logic.
        Session.new(|from-json($d))
    }
}
=end code


# AUTHOR

Denis Kanchev

# COPYRIGHT AND LICENSE

Copyright 2025 Denis Kanchev

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.
