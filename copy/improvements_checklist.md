# Improvements to be done

- Username and Password validation should be there.
- File sharing => Should be shown a list of connected users.
- Connection request => Should be shown list of usernames, some privilleged users will have 'hidden' visibility.
- User should be notified on request accept.
- If user deleted profile, GHOST user profile should be preserved.
- Admin access should be there to a deleted user's profile after profile deletion.
  - Store a 'masterkey_hash' in database and replace the deleted user's 'password_hash' with 'masterkey_hash'.
- User's profile and access rights should be pass on to admin if user deleted their account for some reason.
  - Admin should be able to access the profile, view everyting, but should not be able to modify anything.
- Admin should be able to create accounts for users.
- If user visits the server link and tries to create an account by registering their profile, admin must have to accept the request for registration completion.
- DB should be centralised.
