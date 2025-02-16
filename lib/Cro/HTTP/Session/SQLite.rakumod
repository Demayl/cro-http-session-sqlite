use DBIish;
use DBDish::SQLite::Connection;
use JSON::Fast;
use Cro::HTTP::Session::IdGenerator;
use Cro::HTTP::Middleware;
use OpenSSL::CryptTools;
use MIME::Base64;


#| A Cro HTTP session storage using SQLite. Expects to be parmeterized
#| with the session type.
role Cro::HTTP::Session::SQLite[::TSession] does Cro::HTTP::Middleware::RequestResponse {

	my Supply $supply   	= Nil;
	my Lock::Async $lock 	= Lock::Async.new;

    #| The database connection.
    has DBDish::SQLite::Connection $.db;

	has IO::Path $.db-path 		= 'sessions.db'.IO;

	#| The cookie name or will fail on missing one
    has Str $.cookie-name 		= 'CroCookie';

    #| The duration of the session; defaults to 30 minutes.
    has Duration $.expiration   = Duration.new(30 * 60);

    #| The sessions table name; defaults to 'sessions'.
    has Str $.sessions-table 	= 'sessions';

    #| The session ID column name; defaults to 'id'.
    has Str $.id-column 		= 'id';

    #| The session state column name; defaults to 'state'.
    has Str $.state-column 		= 'state';

    #| The session expiration column; defaults to 'expiration'.
    has Str $.expiration-column = 'expiration';

	#| The ip address column; defaults to 'ip_addr'
	has Str $.ip-addr-column 	= 'ip_addr';

	#| The user ID column; defaults to 'user_id'
	has Str $.user-id-column 	= 'user_id';

	#| Field for the timestamp of record creation; defaults to 'created'
	has Str $.created-column 	= 'created';

	#| The IP address field in the Session object
	has Str $.ip-addr-field 	= 'ip-addr';

	#| The user ID field in the Session object
	has Str $.user-id-field 	= 'user-id';

	#| Whenever to look for the IP address to match the session ID; defaults to True
	has Bool $.restrict-ip-addr = True;

	#| Skips a cookie, use a sub that returns Bool. Passes Cro Request object
	has Callable $.skip-cookie;

	#| Auto clean the sessions from the DB every x seconds; defaults to 1800 (30min)
	#| -1 to disable session clean
	#| 0 to clean on every request
	#| >0 delete the sessions every x seconds
	has Int $.autoclean-every-seconds = 1800;

	#| Encryption key for AES256. See OpenSSL::CryptTools
	has Buf() $.key;

	#| IV see OpenSSL::CryptTools
	has Buf() $.iv;


	submethod TWEAK {
		my $sq = DBIish.install-driver("SQLite");

		fail "Missing SQLite driver. Please install it first!" 		if !$sq || !$sq.library;
		fail "Your SQLite driver is not compiled to be threadsafe!" if !$sq.threadsafe;
		fail "Missing SQLite DBIish connection and db-path argument"if !$!db && !$!db-path;
		fail "Your SQLite version is only {$sq.version} and v3+ is required" if $sq.version < v3;
		fail "You provided a key without an IV" if $!key && !$!iv;
		fail "You provided an IV without a key" if !$!key && $!iv;


		if !$!db { # We use our own DB connection
			$!db = DBIish.connect: "SQLite", database => $!db-path.Str, busy-timeout => 10000, :RaiseError;
		}

		my $sth = $!db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", $!sessions-table);
		my Bool $table-exists = $sth.row.elems != 0;
		$sth.dispose(); # Free the allocated memory of the query

		# Create missing table
		if !$table-exists {
			my $sth = $!db.execute(
				qq:to/END/
				CREATE TABLE IF NOT EXISTS $!sessions-table (
					$!id-column varchar(255), 
					$!state-column json,
					$!ip-addr-column varchar(255),
					$!user-id-column INTEGER,
					$!expiration-column TIMESTAMP,
					$!created-column TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
				)
				END
			);
			$sth.dispose();
			$sth = $!db.execute("CREATE INDEX session_id ON $!sessions-table ($!id-column)"); # For faster select on sessions
			$sth.dispose();
			$sth = $!db.execute("CREATE INDEX expired_date ON $!sessions-table ($!expiration-column)"); # Date expiration
			$sth.dispose();
		}

		if !$supply && $!autoclean-every-seconds > 0 {
			$lock.protect( -> {
				if !$supply.defined {
					$supply = Supply.interval( $!autoclean-every-seconds );
					$supply.act( -> $count {
						self.clear();
					});
				}
			});
		}
	}

    method expiration() { $!expiration }
    method cookie-name() { $!cookie-name }

    #| Creates a new session by making a database table entry.
    method create(Str $session-id) {
		my $sth = $!db.execute("INSERT INTO $!sessions-table ( $!id-column, $!state-column, $!expiration-column )
			VALUES (?, ?, ?)", $session-id, "", (DateTime.now + $!expiration).Str
		);
		$sth.dispose();

    }

    #| Loads a session from the database.
    method load(Str $session-id --> TSession) {
		my $sth 	= $!db.execute("SELECT $!state-column, $!ip-addr-column FROM $!sessions-table WHERE $!id-column = ?", $session-id);
		my $db-data = $sth.row() || fail "Missing session";
		my $data 	= self.deserialize( $db-data.first );
		my $ip-addr = $db-data[1];

		$sth.dispose();

		if $ip-addr && $!restrict-ip-addr && $data.can( $!ip-addr-field ) && $data."$!ip-addr-field"() ne $ip-addr {
			return Nil;
		}

		return $data;
    }

    #| Saves a session to the database.
    method save(Str $session-id, TSession $session --> Nil) {
        my $json 		:= self.serialize($session);

		my @values 		= ( self.encrypt( to-json($json) ) || '{}', (DateTime.now + $!expiration).Str );
		my Str $fields  = "$!state-column = ?, $!expiration-column = ?";



		if $!ip-addr-field and $json{ $!ip-addr-field }:exists {
			$fields ~= ", $!ip-addr-column = ?";
			@values.push( $json{ $!ip-addr-field } );
		}

		if $!user-id-field and $json{ $!user-id-field }:exists {
			$fields ~= ", $!user-id-column = ?";
			@values.push( $json{ $!user-id-field } );
		}

		my $sth = $!db.execute("UPDATE $!sessions-table SET $fields WHERE $!id-column = ?",
			|@values, $session-id
		);
		$sth.dispose();
    }

    #| Clears expired sessions from the database.
    method clear(--> Int) {
		my $sth = $!db.execute("DELETE FROM $!sessions-table WHERE $!expiration-column < ?", DateTime.now.Str);
		my Int $deleted = $sth.rows();
		$sth.dispose();
		$deleted;
    }

    #| Serialize a session for storage. By default, serializes its
    #| public attributes into JSON (obtained by .Capture.hash); for
    #| any non-trivial session state, this shall need to be overridden.
	#| Wont store any uninitialized field
    method serialize(TSession $s --> Hash) {
		my %hash = $s.Capture.hash;

		# JSON::Fast will store arrays as [] and Nil values as Any, so fix it here
		for %hash.kv -> $key, $val {
			if !$val.defined || ( $val ~~ Array && !so $val ) {
				%hash{$key}:delete;
				next;
			}
		}
        %hash
    }

    #| Deserialize a session from storage. By default, passes the
    #| serialized data to the new method of the session. For any
    #| non-trivial state, this will need to be overridden.
    method deserialize(Str $d='') {
        TSession.new(|from-json( self.decrypt($d) ))
    }

    method process-responses(Supply $responses) {
        my %cookie-opts = max-age => $!expiration, :http-only, path => '/';
        supply whenever $responses -> $res {
            with $res.request.cookie-value($!cookie-name) {
                $res.set-cookie($!cookie-name, $_, |%cookie-opts);
                self.save($_, $res.request.auth);
            } orwith $res.request.auth {
				my $content-type = $res.request.header('content-type');
				my $ip-addr = $res.request.connection.peer-host;


                # Setting a cookie if not skipped
				if !$!skip-cookie || !$!skip-cookie.( $res ) {
					my $cookie-value = generate-session-id();
					$res.set-cookie($!cookie-name, $cookie-value, |%cookie-opts);
					my $created = self.create($cookie-value);
					if $created ~~ TSession {
						self.save($cookie-value, $created);
					} else {
						self.save($cookie-value, $res.request.auth);
					}
				}
            }
            emit $res;
		}
    }

	method process-requests(Supply $requests) {
		supply whenever $requests -> $req {
			self.clear() if $!autoclean-every-seconds == 0;
			$req.auth = TSession.new;
			my $cookie-value = $req.cookie-value($!cookie-name);
			if $cookie-value {
				try {
					my $session = self.load($cookie-value);
					$req.auth = $session;
					CATCH {
						default {
							$req.remove-cookie($!cookie-name);
						}
					}
				}
			}
			emit $req;
		}
	}


	#| returns Base64 Str
	method encrypt( Str:D $string --> Str ) {
		return $string if !$!key;
		try MIME::Base64.encode-str(
			encrypt( $string.encode, :aes256, :iv($!iv), :key($!key) ).decode('iso-8859-1')
		)
	}

	multi method decrypt( Str:D $string --> Str ) {
		return $string if !$!key;
		try decrypt(
			MIME::Base64.decode-str($string).encode('iso-8859-1'), :aes256, :iv($!iv), :key($!key)
		).decode('utf8-c8');
	}


}

=begin pod

=head1 NAME

Cro::HTTP::Session::SQLite - An implementation of Cro persistent sessions using SQLite.

=head1 SYNOPSIS

=begin code :lang<raku>

use Cro::HTTP::Session::SQLite;

=end code

=head1 DESCRIPTION

There are dozens of ways we might do session storage; this module handles the case where:

=item The database is being accessed using DBIish.

=item You're fine with the session state being serialized and stored as a JSON in the database.

If these don't meet your needs, it's best to steal the code from this module into your own application and edit it as needed.

=head1 INSTALLATION

=begin code :lang<bash>
zef install Cro::HTTP::Session::SQLite
=end code

=head1 FUNCTIONALITY

=item Store the session data in local SQLite3 file

=item Auto create the db file and table if missing

=item Using your own SQLite DBIish connection if required

=item Encrypted data store using OpenSSL::CryptTools AES256

=item Session auto cleanup or on every request

=item Configurable table name and columns

=item Store the user ID and IP address from the session

=item Skip creating a session

=item JSON state storage in a json type column

=item Base64 state storage when encrypted

=item IP cookie binding


=head1 Database default setup

=item The table name can be changed

=item Every column is configurable

=item The table will be created if missing

=begin code :lang<sql>
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

=end code

=head1 Minimal Cro application setup


=begin code :lang<raku>
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
=end code

Here are the keypoints here:
=item Creates a ./sessions.db file

=item Cookie expiration time is 30 min

=item Auto clean the sessions table every 30 min

=item Prevent session loading if the user IP address doesn't match the stored one

=head1 Custom setup

=begin code :lang<raku>
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
=end code

Here we have a custom setup:

=item Expiration time is B<60 minutes>

=item Cookie name is B<CustomCookieName>

=item SQLite DB file is B</home/user/app/sessions.db>

=item Cookie is restricted only to the IP address previously stored

=item Expired sessions are deleted from the DB every 60 seconds

=item The data is encrypted using a default KEY and IV and you B<must CHANGE IT>

=item Cookie is ignored if the request content type is application/json

For full setup see the constructor below

=head1 Constructor

All fields are optional

=defn DBDish::SQLite::Connection $.db
DBIish connection. B<Default> auto connects

=defn IO::Path $.db-path
Path to the DB SQLite3 file. B<Default> C<./sessions.db>

=defn Str $.cookie-name
Name of the cookie. B<Default> CroCookie

=defn Duration $.expiration
Expiration duration for the cookie. B<Default> C<Duration.new( 30*60 )>

=defn Int $.autoclean-every-seconds
Session cleanup every X seconds. B<Default> 1800

=item2 -1 Disable session removal
=item2 0 Delete the expired sessions on every request
=item2 1+ Delete the expired sessions every X seconds

=defn Str $.sessions-table
Name of the DB table. B<Default> sessions

=defn Str $.id-column
Name of the ID column in the DB. B<Default> id

=defn Str $.state-column
Name of the state column in the DB. B<Default> state

=defn Str $.expiration-column
Name Of the expiration column. B<Default> expiration

=defn Str $.ip-addr-column
Name of the IP address column. B<Default> ip_addr

=defn Str $.user-id-column
Name of the User ID column. B<Default> user_id

=defn Str $.created-column
Name of the Created column. B<Default> created

=defn Str $.ip-addr-field
Field name from your Session object, that is used to store the IP address in the table column $.ip-addr-column. B<Default> ip-addr

=item2 Nil to disable storing the IP address

=defn Str $.user-id-field
Field name from your Session object, that is used to store the User ID in the table column $.user-id-column. B<Default> user-id

=item2 Nil to disable storing the User ID

=defn Bool $.restrict-ip-addr
IP cookie bind. Looksup the $.ip-addr-field from your Session object. B<Default> I<True>

=defn Callable &.skip-cookie
Custom function that can disable the session. B<Default> I<Nil>

=defn Buf() $.key
Encryption key. See L<OpenSSL|https://raku.land/github:sergot/OpenSSL#opensslcrypttools> for more information

=defn Buf() $.iv
IV. See L<OpenSSL|https://raku.land/github:sergot/OpenSSL#opensslcrypttools> for more information

=head1 Controlling serialized data

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


=head1 AUTHOR

Denis Kanchev

=head1 COPYRIGHT AND LICENSE

Copyright 2025 Denis Kanchev

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

=end pod
