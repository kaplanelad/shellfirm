# Add new patterns

1. If you are adding a new group goes to [patterns folder](../shellfirm/checks) and YAML file with the group name.
2. The file includes list of patterns with the following format
    ```yaml
    - from: ""
      test: ""
      description: ""
      id: ""
    ```
    `from`: Should be the same as the group file name.
    
    `test`: Is the pattern Regex. 
    
    `description`: Description of the pattern
    
    `id`: unique pattern name. the id should be in this format: `   {group_name}`:`{pattern_id}`
    
3. We create a unitest for each pattern to test the regex.
    - Go to [shellfirm/test/checks](../shellfirm/tests/checks/) folder and create new pattern test. the format of the file name should be the pattern id. **note** replace the `:` with `-` char
    - the test file should include a list of tests with the following format:
        ```yaml
        - test: crontab -r
        description: match command
        ```
4. Run `cargo insta test --review` to validate and approve your snapshot
5. You can also run the command `cargo run pre-command --command "COMMAND"` to check the integration when executing shellfirm binary
