# RECapk

:rocket: ## Automate finding of secrets in latest and old apk's of target.

<img width="732" height="314" alt="Screenshot 2025-07-27 at 20 32 37" src="https://github.com/user-attachments/assets/c4220020-aaaf-4bd6-888e-8bc3f2dabff5" />

This is a one of its kind of tool to perform one of the crucial step while performing recon on Android apps. Imagine that you are performing pentesting on an Android application. The most common step is to reverse engineer the target apk and look for code and juicy sensitive info inside the apk file. 
Most of you might be aware of it and you look for only the latest version of apk build. But what if the secrets, tokens, hidden domains might get leaked in previous / older versions of same targets older apk builds and these juicy info was removed in latest build and those secrets and tokens are still in active. (Personally I've seen many vulnerabilities by doing this approach). 
> This is one of the most hidden step in Android recon.

Can't we automate this approach ? Because downloading all apk's, reverse engineer, scanning, looking out for secrets, etc.

Here comes RECapk tool in handy. You just need to provide the target's APKpure link in the text file and rest this tool will take care. Below are the tasks it does:

- Creates a separate scan folder on running the script
- Download latest and previous 10 versions apk builds of target application mentioned in the .txt file in the created scan folder
- Installs apkscan tool if its not installed already
- Does reverse engineer on the downloaded 10 apk builds of the target
- Then it generates the .html findings report

## Usage:

> git clone https://github.com/praseudo/recapk

> cd recapk

> python3 recapk.py

Make sure to mention the list of target applications APKPure URL's in a .txt file like:
Search for Netflix in https://apkpure.net and click on all versions then select the URL which looks like this https://apkpure.net/netflix/com.netflix.mediaclient/versions (You can add multiple target application URL's in the .txt file)

Example .txt file should look like:

> https://apkpure.net/netflix/com.netflix.mediaclient/versions

> https://apkpure.net/facebook/com.facebook.katana/versions

> and so on ...

## Screenshot:

<img width="2570" height="1702" alt="Screenshot 2025-07-29 at 22 58 12" src="https://github.com/user-attachments/assets/9ef832c9-d166-4d11-8a11-a4b6ac7a80c4" />


Make sure to add this tool in your android pentesting recon phase. You won't regret it. 

👉 More additions in progress. Stay tuned !!!



🙌 Please do follow and star this Github repo if you like it.



