# CredPrompt

BOF implementation of @matterpreter's [CredPhisher](https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher) project and @spottheplanet [article](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/credentials-collection-via-creduipromptforcredentials). It is using `CredUIPromptForWindowsCredentials` to ask current user credentials.

Note that until the user has not enter credential or close the prompt, the beacon won't be able reachable.

## Compile

```
make
```

## Usage

Load the provided aggressor script. Credprompt without argument will use the default message `Windows has lost connection to Outlook`.

```
credprompt
```

Using your own message :
```
credprompt "Hello from BOF"
```