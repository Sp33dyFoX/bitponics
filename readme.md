README
======

Environment Setup & Workflow:
https://docs.google.com/a/bitponics.com/document/d/145qi_CohjhT_qwwhXuA3bZy65cpnOlgrVQ4cQ506baE/edit


To run tests, use the same command that's in package.json scripts.test:
> ./node_modules/.bin/mocha --reporter spec --recursive --timeout 15000 --slow 50 ./test/back-end

To run a specific test, use the grep flag:
> ./node_modules/.bin/mocha --reporter spec --recursive --timeout 15000 --slow 50 ./test/back-end --grep "name of my test"


#### Environment Variables

- BPN_EMAIL_ON_ERRORS
  
  Enables winston-nodemailer, which will email engineering@bitponics.com for all errors & exceptions.
- BPN_BLOG_ENABLED
  
  Determines whether /blog route is enabled.
