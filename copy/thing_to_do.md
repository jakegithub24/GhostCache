# Things To Do

1. In chat there should be 'username' instead of 'user_id'. f"Chat with {{ username }}"
2. In 'Search for users' if user searches for 'myad' then app shows 'myadmin' user. It should show profile (connect-btn) only when exact 'username'(input) matches.
3. 'user list' should be shown to admin.
  - List of 'visible' users
  - List of 'hidden' users
4. If user deleted their account, non-deleted account shouldn't be able to send messages to deleted account. Deleted account shouldn't receive any messages or connection requests.
5. 'Hidden' user's username shouldn't be searched by any user except 'admin'. Even another hidden users also should not be able to search other hidden users and send them connection request and share files.
6. There should be a page 'manage users' in admin dashboard.
  - Lists
    - Visible users
    - Hidden users
  - Options
    - Delete users (only physical delete, not logical)
    - View connections (every user's connection to other users)
7. Admin should get notified for every connection request and its acceptance or denial. For example : 'visible' to 'visible' and 'hidden' to 'visible'.
8. Warning of "Account deleted (destruction password used)" should not be displayed. Account should get deleted silently. 
