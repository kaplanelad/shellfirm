# Heroku Checks:

- Detect dynos restart/stop and kill.

- Detect maintenance enabled on app.

- Detect when removing members.

- Detect when disable feature.

- Detect when remove container.

- Detect when unset config.

- Detect when destroy/rotate and update Oath clients.

- Detect when destroy/leave and rename app.

- Detect when destroy/detach/remove and update addons.

* `heroku ps:restart` - This command restarts app dynos and prompts for confirmation.

* `heroku ps:stop` - This command stops app dynos and prompts for confirmation.

* `heroku ps:kill` - This command kills app dynos and prompts for confirmation.

* `heroku maintenance:on` - This command puts the app into maintenance mode and prompts for confirmation.

* `heroku members:remove {USER}` - This command removes a user from a team and prompts for confirmation.

* `heroku features:disable {FEATURE}` - This command disables an app feature and prompts for confirmation.

* `heroku container:rm {PROCESS}` - This command removes the process type from your app and prompts for confirmation.

* `heroku config:unset {VARS}` - This command unsets one or more config vars and prompts for confirmation.

* `heroku clients:destroy {ID}` - This command deletes a client by ID and prompts for confirmation.

* `heroku clients:rotate {ID}` - This command rotates an OAuth client secret and prompts for confirmation.

* `heroku clients:update {ID}` - This command updates an OAuth client and prompts for confirmation.

* `heroku apps:destroy {APP}` - This command permanently destroys an app and prompts for confirmation.

* `heroku apps:leave {APP}` - This command removes yourself from a team app and prompts for confirmation.

* `heroku apps:rename {NEW_NAME}` - This command renames an app and prompts for confirmation.

* `heroku addons:destroy {ADDON}` - This command permanently destroys an add-on resource and prompts for confirmation.

* `heroku addons:detach {ADDON}` - This command detaches an existing add-on resource from an app and prompts for confirmation.

* `heroku access:remove {USER}` - This command removes users from a team app and prompts for confirmation.

* `heroku access:update {USER}` - This command updates existing collaborators on a team app and prompts for confirmation.

* `heroku repo:reset` - This command resets the Heroku repo and prompts for confirmation.
