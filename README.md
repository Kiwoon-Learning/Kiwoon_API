Kiwoon Api:

Default domain will typically be 'tymur.studio'

Eg: http://tymur.studio/api/#######

How does authentication work?
Authentication will be supplied with a JWT. A Jwt is a type of token that is encrypted and contains all user data. They expire in 5 hours. That's basically it.
Pass JWT in 'Authentication' header of your request with format 'Bearer <token>'.
Will return 401 Unauthorized if token is not supplied; 403 Forbidden if token is supplied but is incorrect.

How is it hosted?
The API is hosted in Kubernetes under a Nginx reverse proxy. The proxy handles HTTPS but terminates it to HTTP from proxy-api to improve performance.
Kubernetes is a service which allows you to host applications in 'pods' which are separate from each other and can be scaled to multiple computers.
A reverse proxy handles requests and sends them to the API to be processed. Having the API exposed on its own is dangerous.

===Requests===
GET: api/user (Needs authorization)
Returns user details based on the token submitted.

POST: api/user?email=[EMAIL]&password=[PASSWORD]
Creates a new user with said email and password. No two users can have the same email.

DELETE: api/user?password=[PASSWORD] (Needs authorization)
Deletes the user supplied from the token. Requires correct password to confirm delete request.

GET: api/user/id/{put id here}
Finds user by id and returns it. If no user is found, it doesn't return a user.

POST: api/user/claim/{put claim here} (Needs authorization) ***TEMPORARY METHOD***
A claim is a sort of permission or rank. Think of it as a role: a teacher has a teacher claim, student has student claim.
Creates a claim for the specified user from the token.

GET: api/email?email={EMAIL}
Finds user by email.

PUT: api/email?email={EMAIL}&newEmail={NEWEMAIL} (Needs authorization)
Finds user based on token. Changes their email to the new email, only if their current email matches their input for 'email'.