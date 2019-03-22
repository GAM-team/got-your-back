@echo(
@set /p adminemail= "Please enter your Google email address: "

:createproject
@gyb --action create-project --email %adminemail%
@if not ERRORLEVEL 1 goto projectdone
@echo(
@echo Projection creation failed. Trying again. Say n to skip projection creation.
@goto createproject
:projectdone

:saauth
@echo(
@set /p yn= "Are you a G Suite admin backing up user mail? [y or n] "
@if /I "%yn%"=="n" (
@  echo(
@  echo You can authorize a service account later by running:
@  echo(
@  echo gyb --email %adminemail% --action check-service-account
@  goto sadone
   )
@if /I not "%yn%"=="y" (
@  echo(
@  echo Please answer y or n.
@  goto saauth
   )
@echo(
@set /p regularuser= "Please enter the email address of a regular G Suite user: "
@echo Great! Checking service account scopes. This will fail the first time. Follow the steps to authorize and retry. It can take a few minutes for scopes to PASS after they've been authorized in the admin console.
@gyb --email %regularuser% --action check-service-account
@if not ERRORLEVEL 1 goto sadone
@echo(
@echo Service account authorization failed. Confirm you entered the scopes correctly in the admin console. It can take a few minutes for scopes to PASS after they are entered in the admin console so if you're sure you entered them correctly, go grab a coffee and then hit Y to try again. Say N to skip admin authorization.
@goto saauth
:sadone

@echo GYB installation and setup complete!
:alldone
@pause
