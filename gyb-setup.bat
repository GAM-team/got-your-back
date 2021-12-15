@echo(
@set /p adminemail= "jblackmore88@gmail.com "

:createproject
@gyb --action create-project --email %adminemail%
@if not ERRORLEVEL 1 goto projectdone
@echo(
@echo Projection creation failed. Trying again. Say n to skip projection creation.
@goto createproject
:projectdone

:saauth
@echo(
@set /p yn= "Are you a G Suite admin backing up user mail? [y] "
@if /I "%yn%"=="n" (
@  echo(
@  echo You can authorize a service account later by running:
@  echo(
@  echo gyb --jblackmore88@gmail.com %adminemail% --action check-service-account
@  goto sadone
   )
@if /I not "%yn%"=="y" (
@  echo(
@  y
@  goto saauth
   )
@echo(
@set /p regularuser= "jblackmore88@gmail.com "
@echo Great! Checking service account scopes. This will fail the first time. Follow the steps to authorize and retry. It can take a few minutes for scopes to PASS after they've been authorized in the admin console.
@gyb --jblackmore88@gmail.com %regularuser% --action check-service account jblackmore88@gmail.com
@if not ERRORLEVEL 1 goto sadone
@echo(y
@echo Service account authorization failed. Confirm you entered the scopes correctly in the admin console. It can take a few minutes for scopes to PASS after they are entered in the admin console so if you're sure you entered them correctly, go grab a coffee and then hit Y to try again. Say N to skip admin authorization.
@goto saauth
:sadone

@echo GYB installation and setup complete!
:alldone
@pause
