# THCon21 - Reversing - draw.per

## Static android malware analysis with a second stage payload.

/!\ Disclaimer : please run the provided malicious Android app in a isolated environment (emulator or virtual machine) ! Not on your own device !

While searching for a nice drawing app for your Android phone, you stumbled across this mysterious application. For what nefarious purposes could this app be used ? It's up to you to find out ! Your mission ? Find a way to prevent the malware from executing ! This should hopefully lead you to the flag...

Many thanks to Zephyr for his great ideas !

Files:

    draw.apk

Creators : Sherwin (Discord: Sh#4802) and Jrjgjk (Discord: guilhem#8743)

## A note on this writeup.

I solved this very quickly, I made the right guesses and got to the solve while avoiding rabbit holes (a good grep + familiarity with the kind of chall goes a long way). However, I don't want to simply tell you guys to "draw the rest of the owl", so I'm including those rabbit holes. A thorough investigation is what you absolutely should do when dissecting real world malware, and I wanted to take the chance to explain APK internals and the methodology I usually use for these challenge. You'll likely notice some redundancy, and parts of this writeup essentially just exist to confirm other sections.

## A quick discussion on tools.

For apks I use the following tools to analyse them. This is a slightly non-standard stack so I wanted to share it early on in the writeup.

- `apktool`, this lets me easily dump the contents of an apk into smali (android assembly basically), xml files, and any other assets used.
- `d2j-dex2jar`, this lets me convert an apk into a jar. This is so I can run jar-based tools on the apk.
- `jd-gui`, an excellent java decompiler that can decompile *most* java bytecode back to java effortlessly. [The project lives online at this website](http://java-decompiler.github.io/).

As soon as I have the apk downloaded I run `apktool d draw.apk` which I will begin analysing core files. This is followed by `d2j-dex2jar draw.apk` so I can use jd-gui later on.

## Triage

The dex2jar conversion can take some time, so first I go ahead and use apktool to dump the apk's contents. This can be done with `apktool d draw.apk` as discussed previously. This shows us the following folder/file structure, indicating this APK made us of Kotlin instead of standard Java. This shouldn't impact much, but just know that Kotlin is essentially a Java variant, another programming language that runs on the Java Virtual Machine similar to Scala.

```
drwxr-xr-x   8 bee bee  4096 Jun 14 10:14 .
drwxr-xr-x   3 bee bee  4096 Jun 14 10:15 ..
-rw-r--r--   1 bee bee 14602 Jun 14 10:14 AndroidManifest.xml
-rw-r--r--   1 bee bee 23916 Jun 14 10:14 apktool.yml
drwxr-xr-x   8 bee bee  4096 Jun 14 10:14 kotlin
drwxr-xr-x   3 bee bee  4096 Jun 14 10:14 original
drwxr-xr-x 178 bee bee  4096 Jun 14 10:14 res
drwxr-xr-x   8 bee bee  4096 Jun 14 10:14 smali
drwxr-xr-x   4 bee bee  4096 Jun 14 10:14 smali_classes2
drwxr-xr-x   3 bee bee  4096 Jun 14 10:14 unknown
```

If you're not familiar with the structure of APK files and Android developments, `AndroidManifest.xml` is the glue that holds everything together. It describes exactly what the app will do and provides information on how it operates, where the start point for the program is and what classs are part of different intents. We'll be examining this before anything else.

### Permissions

First of all, the manifest defines the permissions needed by the application. Since this is likely malware, the permissions it requires should give us a clue as to what it is attempting to do.

```xml
    <uses-permission android:maxSdkVersion="28" android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.SET_WALLPAPER"/>
    <uses-feature android:name="android.hardware.faketouch" android:required="false"/>
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
    <uses-feature android:name="android.hardware.screen.portrait" android:required="false"/>
```

First of all, ignore the `uses-feature` sections, they aren't very important here. What is important is the permission, the first 3 of which describe what the malware intends to do to us, albeit out of order. It needs internet access, likely to download the second stage payload. This payload will be stored in external storage. The payload will then be used to set the wallpaper. It isn't strictly required that you make this guess, but it is an accurate one!

### Main Activity

Additionally, the manifest defines the class called on entry. This is similar to the entrypoint in an ELF file.

```xml
        <activity-alias android:enabled="false" android:icon="@mipmap/ic_launcher_grey_black" android:name="com.simplemobiletools.draw.pro.activities.SplashActivity.Grey_black" android:roundIcon="@mipmap/ic_launcher_grey_black" android:targetActivity="com.simplemobiletools.draw.pro.activities.SplashActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity-alias>
```

The summary of this xml is that the first thing to be called will the activity `com.simplemobiletools.draw.pro.activities.SplashActivity`. This should correspond to a splashscreen of sorts, welcoming you the program. This appears to be the best place to begin static analysis, so I fire up `jd-gui` and open up our dex2jar conversion.

Navigating to the correct class, I get the follow decompiled Java:

```java
package com.simplemobiletools.draw.pro.activities;

import android.content.Context;
import android.content.Intent;
import android.view.View;
import com.simplemobiletools.commons.activities.BaseSplashActivity;
import java.util.HashMap;
import kotlin.Metadata;

@Metadata(bv = {1, 0, 3}, d1 = {"\000\022\n\002\030\002\n\002\030\002\n\002\b\002\n\002\020\002\n\000\030\0002\0020\001B\005��\006\002\020\002J\b\020\003\032\0020\004H\026��\006\005"}, d2 = {"Lcom/simplemobiletools/draw/pro/activities/SplashActivity;", "Lcom/simplemobiletools/commons/activities/BaseSplashActivity;", "()V", "initActivity", "", "draw_debug"}, k = 1, mv = {1, 4, 2})
public final class SplashActivity extends BaseSplashActivity {
  private HashMap _$_findViewCache;
  
  public void _$_clearFindViewByIdCache() {
    HashMap hashMap = this._$_findViewCache;
    if (hashMap != null)
      hashMap.clear(); 
  }
  
  public View _$_findCachedViewById(int paramInt) {
    if (this._$_findViewCache == null)
      this._$_findViewCache = new HashMap(); 
    View view1 = (View)this._$_findViewCache.get(Integer.valueOf(paramInt));
    View view2 = view1;
    if (view1 == null) {
      view2 = findViewById(paramInt);
      this._$_findViewCache.put(Integer.valueOf(paramInt), view2);
    } 
    return view2;
  }
  
  public void initActivity() {
    startActivity(new Intent((Context)this, MainActivity.class));
    finish();
  }
}

```

This is surprisingly straightforward to understand with a bit of understanding of "broader software ideas". Splashscreens appear for a few seconds before calling the main program. This code has an `initActivity` function that starts and activity labelled `MainActivity.class`. Therefore, we should probably move on to `MainActivity` which is likely the real "Main" function at play here. This class contains many functions that seem to be related to drawing. I included a snippet below. Sadly, none of these appear to be related to the malware tendencies.

```java
private final void checkWhatsNewDialog() {
    ArrayList arrayList = new ArrayList();
    arrayList.add(new Release(18, 2131755541));
    arrayList.add(new Release(20, 2131755542));
    arrayList.add(new Release(38, 2131755543));
    ActivityKt.checkWhatsNew(this, (List)arrayList, 59);
  }
  
  private final void clearCanvas() {
    this.uriToLoad = (Uri)null;
    ((MyCanvas)_$_findCachedViewById(R.id.my_canvas)).clearCanvas();
    this.defaultExtension = "png";
    this.defaultPath = "";
    this.lastBitmapPath = "";
  }
```

## Hunting for the malicious parts

Since there is a lot of code involved in the draw.per apk, it is probably best to locate areas of interest. We can do this by searching specific files and by searching for interesting strings in all files.


### The strings file.

The APK strings reference at `res/values/strings.xml` will define *most* strings used in an Android application. This largely occurs for localization purposes, so the values can be changed for different languages. It also gives us a central repository of interesting strings. Inside are 3 strings of interest that can be found by scrolling through the several hundred lines.

```xml
    <string name="settings_1">$tr1ng$_@r3_r3@lly_pr@ct1c@l</string>
    <string name="settings_2">$up3r_s3cur3d_1v</string>
```

First of all, these weird strings are clearly CTF related based on the hacker-speak involved. Additionally, one of them references being an IV, or initialization vector.

```xml
    <string name="data_privacy_url">https://challenges.thcon.party/reverse-jrjgjk-stI1gar-draw.per/cisc42M3HNc6tL3wOnJqjenvrihddn/files.zip</string>
```
This string points towards a suspicious ZIP file hosted by the CTF. It very likely contains interesting information and I'll examine it a bit further into the writeup.

### Grepping for interesting bits.

There are 3 grep statements that can uncover information about the malware. APKTool did the heavy lifting of extracting the APKs files as well as converting the JVM bytecode to greppable smali files, so we can basically just grep for anything we want.

#### Grepping for the flag in plaintext.

This CTF had a flag format of `THCon21`. So naturally, I grepped for `thcon` first thing with a case insensitive recursive search. The exact command was `grep -i thcon -r .`. This uncovered the following in `strings.xml`. While we found this same string through analysing this xml file previously, it would be faster to just find it quickly with grep.

```
./strings.xml:    <string name="data_privacy_url">https://challenges.thcon.party/reverse-jrjgjk-stI1gar-draw.per/cisc42M3HNc6tL3wOnJqjenvrihddn/files.zip</string>
```

#### Grepping for all URLs.

I could also have connected the dots that the internet permission was used, and as such I should search for URLs in general. The command `grep -i http -r .` works well for this.

```
(like 20 hits in individual smali fles)
./strings.xml:https://www.apache.org/licenses/LICENSE-2.0
./strings.xml:    <string name="apng_url">https://github.com/penfeizhou/APNG4Android</string>
./strings.xml:    <string name="app_long_description">"a long winded description I cut out for brevity "<b>Check out the full suite of Simple Tools here:</b> https://www.simplemobiletools.com <b>Facebook:</b> https://www.facebook.com/simplemobiletools <b>Reddit:</b>" https://www.reddit.com/r/SimpleMobileTools "</string>
./strings.xml:https://www.apache.org/licenses/LICENSE-2.0
./strings.xml:    <string name="audio_record_view_url">https://github.com/Armen101/AudioRecordView</string>
./strings.xml:https://www.apache.org/licenses/LICENSE-2.0
./strings.xml:    <string name="autofittextview_url">https://github.com/grantland/android-autofittextview</string>
./strings.xml:https://www.apache.org/licenses/LICENSE-2.0
./strings.xml:    <string name="cropper_url">https://github.com/ArthurHub/Android-Image-Cropper</string>
./strings.xml:    <string name="data_privacy_url">https://challenges.thcon.party/reverse-jrjgjk-stI1gar-draw.per/cisc42M3HNc6tL3wOnJqjenvrihddn/files.zip</string>
(lots more URLs followed)
```

As you can see it was way less specific and turned up far more results! However, it did identify the URL with the sucpicious zip.

#### Grepping for encryption routines.

We know that this program has an initialization vector. Initialization vectors are most commonly used in block ciphers such as AES, typically AES-CBC mode. So, I went ahead and grepped for AES with `grep -i AES -r .`. This yielded the following results and showed that the SettingsActivity likely used AES!

```
./smali_classes2/com/simplemobiletools/draw/pro/activities/SettingsActivity.smali:    const-string v7, "AES"
./smali_classes2/com/simplemobiletools/draw/pro/activities/SettingsActivity.smali:    const-string v5, "AES_256/CBC/PKCS7Padding"
./original/META-INF/CERT.SF:SHA-256-Digest: MI2o9PEawOHJLT8AlqaEsQXblUJWFk4ZkOe0bruS/lY=
./original/META-INF/CERT.SF:SHA-256-Digest: 0SqViuqOaesijd3OmkZhBYaY2GQKrIlvQVKFM7enj1E=
./original/META-INF/MANIFEST.MF:SHA-256-Digest: AlmrvKG5hXG6GcmhxOAeSNc5apYO5Q98u0ttFBPY51M=
grep: ./unknown/org/joda/time/tz/data/Antarctica/Macquarie: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Melbourne: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Broken_Hill: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Lord_Howe: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Lindeman: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Brisbane: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Currie: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Sydney: binary file matches
grep: ./unknown/org/joda/time/tz/data/Australia/Hobart: binary file matches
grep: ./res/mipmap-xxhdpi/ic_launcher_yellow.png: binary file matches
./res/values-cy/strings.xml:    <string name="faq_2_text_commons">"Oes, wrth gwrs. Gallet ddweud wrth eraill mor dda yw'r apiau neu roi adborth a sgôr da. Gallet hefyd helpu ehangu a chywiro cyfieithiadau i'r Gymraeg a ieithoedd eraill. Mae canllaw yma https://github.com/SimpleMobileTools/General-Discussion , neu anfona ebost ata'i (yn Saesneg) hello@simplemobiletools.com os oes angen help."</string>
./res/values-cy/strings.xml:    <string name="use_english_language">Defnyddio Saesneg</string>
./res/values-fi/strings.xml:    <string name="skip_delete_confirmation">Älä koskaan kysy varmistusta tiedostoja poistaessa</string>
./res/values-fi/strings.xml:    <string name="vibrate_on_button_press">Tärinä koskettaessa</string>
```

### The zip file.

We went ahead and downloaded the zip file for analysis. This can be done easily with `wget https://challenges.thcon.party/reverse-jrjgjk-stI1gar-draw.per/cisc42M3HNc6tL3wOnJqjenvrihddn/files.zip` and then `unzip files.zip`.

```
Archive:  files.zip
 extracting: ExtClass.enc            
 extracting: inf.enc                 
  inflating: theme.jpg    
```

As a note, you can see that the `.enc` files we extracted and not inflated. That is because they have a high entropy and cannot be compressed. This is likely because they are encrypted.

Additionally, the file theme.jpg is clearly a wallpaper, which makes sense given we know the malware likely wants to change ours. Here is a picture of it.

![Screenshot showing the wallpaper](../assets/THC-drawper-theme.jpg)

Additionally, we can identify what uses this zip in two different ways, most of which involve use of grep.

#### GREPing for ".enc".

Running `grep -i "\.enc" -r .` will find all files that mentioned ".enc". Note that the period needs to be escaped, thats because it is a wildcard in grep and matches any character, adding the backslash means it will be interpeted as a standard period. We get a hit in "SettingsActivity.smali", which as you may remember is where we saw the string "AES" previously.

```
./draw/smali_classes2/com/simplemobiletools/draw/pro/activities/SettingsActivity.smali:    const-string v1, "ExtClass.enc"
./draw/smali/com/bumptech/glide/load/engine/DecodeJob$DeferredEncodeManager.smali:    const-string v0, "DecodeJob.encode"
grep: ./files.zip: binary file matches
```

#### GREPing for "data_privacy_url".

We know from the strings.xml file that the name for the link to the zip is "data_privacy_url". This name will appear in most every place that wants to access the string . While there is also an integer representation of the string name that will be defined which can be grepped for, that was not needed in this case. 

```
./draw/smali_classes2/com/simplemobiletools/draw/pro/R$string.smali:.field public static final data_privacy_url:I = 0x7f100094
./draw/smali_classes2/com/simplemobiletools/draw/pro/activities/SettingsActivity.smali:    const-string v5, "getString(R.string.data_privacy_url)"
./draw/res/values/strings.xml:    <string name="data_privacy_url">https://challenges.thcon.party/reverse-jrjgjk-stI1gar-draw.per/cisc42M3HNc6tL3wOnJqjenvrihddn/files.zip</string>
./draw/res/values/public.xml:    <public type="string" name="data_privacy_url" id="0x7f100094" />
```

As mentioned previously, that last entry included the integer representation. As an example, here is what happens when you grep for that number with `grep -i "0x7f100094" -r .`.

```
./draw/smali_classes2/com/simplemobiletools/draw/pro/R$string.smali:.field public static final data_privacy_url:I = 0x7f100094
./draw/smali_classes2/com/simplemobiletools/draw/pro/activities/SettingsActivity.smali:    const v5, 0x7f100094
./draw/res/values/public.xml:    <public type="string" name="data_privacy_url" id="0x7f100094" />
```

So, once again we know the URL is used in SettingsActivity. Since it is very clearly proven SettingsActivity is what we need to look at, I'll move on to examining that class.

## SettingsActivity, our beautiful dropper.

So now we know SettingsActivty is the area of interest, we can just fire it up in jd-gui!

```java
// INTERNAL ERROR //
```

Well, jd-gui clearly doesn't like this file. It probably uses some nonstandard bytecode, perhaps it was written in kotlin and didn't convert good. I can't be sure why, but in this case it seems that we'll be having to parse the "smali" files instead. Now, this looks kind of intimidating and it often is difficult. However, we can make use of educated guesses to avoid most of the pain of deciphering bytecode!

Now, as a first note, there are actually several different emali files. I believe there is a seperate one for certain functions based on whether or not they are static but I don't know for sure. As a sidenote, seeing a file named "executePayload" is a great sign that something malicious is going on!

```
-rw-r--r-- 1 bee bee  7678 Jun 14 10:14 'SettingsActivity$executePayload$1$1.smali'
-rw-r--r-- 1 bee bee  7947 Jun 14 10:14 'SettingsActivity$executePayload$1.smali'
-rw-r--r-- 1 bee bee  7754 Jun 14 10:14 'SettingsActivity$loadServerFiles$1$job$1.smali'
-rw-r--r-- 1 bee bee  8918 Jun 14 10:14 'SettingsActivity$loadServerFiles$1.smali'
-rw-r--r-- 1 bee bee  5606 Jun 14 10:14 'SettingsActivity$onResume$1.smali'
-rw-r--r-- 1 bee bee  3651 Jun 14 10:14 'SettingsActivity$setupAllowZoomingCanvas$1.smali'
-rw-r--r-- 1 bee bee  3577 Jun 14 10:14 'SettingsActivity$setupBrushSize$1.smali'
-rw-r--r-- 1 bee bee  2057 Jun 14 10:14 'SettingsActivity$setupCustomizeColors$1.smali'
-rw-r--r-- 1 bee bee  3626 Jun 14 10:14 'SettingsActivity$setupForcePortraitMode$1.smali'
-rw-r--r-- 1 bee bee  3714 Jun 14 10:14 'SettingsActivity$setupPreventPhoneFromSleeping$1.smali'
-rw-r--r-- 1 bee bee  3656 Jun 14 10:14 'SettingsActivity$setupUseEnglish$1.smali'
-rw-r--r-- 1 bee bee  3223 Jun 14 10:14 'SettingsActivity$toHexString$1.smali'
-rw-r--r-- 1 bee bee 65453 Jun 14 10:14  SettingsActivity.smali
```

We know from the grep statements previously that `SettingsActivity.smali` contains the AES encryption routines, so we'll be focusing there.

Here are the contents of the function in SettingsActivity.smali that actually handles the encryption, or in this case decryption. I'll walk you through it.

```java
.method private final decryptPayload(Ljava/lang/String;Ljava/lang/String;)V
    .locals 11
    .param p1, "encpath"    # Ljava/lang/String;
    .param p2, "decpath"    # Ljava/lang/String;
```
This is naming the arguments passed to the function. "encpath" likely contains the path to what is to be decrypted, and "decpath" will be where it is outputted.
```java
    .line 158
    const v0, 0x7f100257
```
We can cross reference this number with `res/values/public.xml` to find `<public type="string" name="settings_1" id="0x7f100257" />`. We can then look up `settings_1` in `strings.xml` to find it maps to the string "$tr1ng$_@r3_r3@lly_pr@ct1c@l". 

```java

    invoke-virtual {p0, v0}, Lcom/simplemobiletools/draw/pro/activities/SettingsActivity;->getString(I)Ljava/lang/String;

    move-result-object v0

    const-string v1, "getString(R.string.settings_1)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V
```
This is likely just more of the string loading routine. v1 holds what is likely the original source of this segment and it is passed to `checkNotNullExpressionValue`. I'm not certain, but that is likely so a nice error can be thrown if the string is null. Don't worry too much about this, just know v0 holds the string.

```java

    .line 159
    .local v0, "pass":Ljava/lang/String;
```
v0 is given the name "pass", likely a reference to password.

```java
    const v1, 0x7f100258

    invoke-virtual {p0, v1}, Lcom/simplemobiletools/draw/pro/activities/SettingsActivity;->getString(I)Ljava/lang/String;

    move-result-object v1

    const-string v2, "getString(R.string.settings_2)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .local v1, "ivs":Ljava/lang/String;
```
This is the exact same paradigm as before, but with `settings_2` and the name "ivs" instead. This lives on in the pseudo-register of v1.
```java
    const-string v2, "SHA-256"

    invoke-static {v2}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v2

    .line 162
    .local v2, "md":Ljava/security/MessageDigest;
```
This is creating a SHA-256 MessageDigest object. Basically, we're getting ready to hash with SHA-256.
```java
    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;

    sget-object v4, Lkotlin/text/Charsets;->UTF_8:Ljava/nio/charset/Charset;

    const-string v5, "null cannot be cast to non-null type java.lang.String"

    if-eqz v0, :cond_1
```

Some boilerplate to create SecretKeySpec and store it in v3. Java encryption libraries make use of these key specs, typically create from strings, in order to select an algorithm to be used.

```java
    invoke-virtual {v0, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v4

    const-string v6, "(this as java.lang.String).getBytes(charset)"

    invoke-static {v4, v6}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V
```
This moves v0 (the pass string) into v4 after having converted it to raw bytes. This will be used in the next section.

```java
    invoke-virtual {v2, v4}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object v4
```
v4, the raw bytes of the pass string, are now fed into SHA-256. The resulting hash is moved into v4. v4 is now equal to `sha256(settings_1)`
```java
    const-string v7, "AES"

    invoke-direct {v3, v4, v7}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 163
    .local v3, "key":Ljavax/crypto/spec/SecretKeySpec;
```
This takes v3 (the SecretKeySpec object), v4 (the hash of the password), and v7 (the "AES" string or the algorithm) and creates the corresponding key. v3 now holds our encryption key.
```java
    new-instance v4, Ljavax/crypto/spec/IvParameterSpec;

    sget-object v7, Lkotlin/text/Charsets;->UTF_8:Ljava/nio/charset/Charset;

    if-eqz v1, :cond_0

    invoke-virtual {v1, v7}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v5

    invoke-static {v5, v6}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v4, v5}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 165
    .local v4, "iv":Ljavax/crypto/spec/IvParameterSpec;
```
This does almost the exact thing as above, but instead with the IV. The IV notably is not hashed however.
```java
    const-string v5, "AES_256/CBC/PKCS7Padding"

    invoke-static {v5}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v5

    .line 166
    .local v5, "cipher":Ljavax/crypto/Cipher;
    const/4 v6, 0x2

    move-object v7, v3

    check-cast v7, Ljava/security/Key;

    move-object v8, v4

    check-cast v8, Ljava/security/spec/AlgorithmParameterSpec;

    invoke-virtual {v5, v6, v7, v8}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V
```
The program now initializes the AES_256 CBC cipher with the key and IV that we've discussed previously. We now have all the information we need to decrypt "ExtClass.enc"! I've included the rest of the smali here simply for educational purposes if anyone wants to study it, it is not needed to complete the challenge.

```java
    .line 168
    new-instance v6, Ljava/io/File;

    invoke-direct {v6, p1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 169
    .local v6, "encfile":Ljava/io/File;
    invoke-static {v6}, Lkotlin/io/FilesKt;->readBytes(Ljava/io/File;)[B

    move-result-object v7

    .line 170
    .local v7, "ciphertext":[B
    invoke-virtual {v5, v7}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object v8

    .line 172
    .local v8, "cleartext":[B
    new-instance v9, Ljava/io/File;

    invoke-direct {v9, p2}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 173
    .local v9, "decfile":Ljava/io/File;
    const-string v10, "cleartext"

    invoke-static {v8, v10}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v9, v8}, Lkotlin/io/FilesKt;->writeBytes(Ljava/io/File;[B)V

    .line 174
    return-void

    .line 163
    .end local v4    # "iv":Ljavax/crypto/spec/IvParameterSpec;
    .end local v5    # "cipher":Ljavax/crypto/Cipher;
    .end local v6    # "encfile":Ljava/io/File;
    .end local v7    # "ciphertext":[B
    .end local v8    # "cleartext":[B
    .end local v9    # "decfile":Ljava/io/File;
    :cond_0
    new-instance v4, Ljava/lang/NullPointerException;

    invoke-direct {v4, v5}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v4

    .line 162
    .end local v3    # "key":Ljavax/crypto/spec/SecretKeySpec;
    :cond_1
    new-instance v3, Ljava/lang/NullPointerException;

    invoke-direct {v3, v5}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v3
.end method
```

## ExtClass.enc

Now we understand SettingsActivity, we can decrypt ExtClass using good old python! As a note, make sure you have PyCryptoDome installed. Also, I know I didn't properly unpad it, but a bit of extra data on the end never hurt anybody.

```python
import hashlib

from Crypto.Cipher import AES


password = b"$tr1ng$_@r3_r3@lly_pr@ct1c@l"
IV = b"$up3r_s3cur3d_1v"


m = hashlib.sha256()
m.update(password)
key = m.digest()

cipher = AES.new(key, AES.MODE_CBC, IV)

f = open("ExtClass.enc", "rb")
ct = f.read()

pt = cipher.decrypt(ct)

f2 = open("ExtClass.dec", "wb")

f2.write(pt)
```

This should read the original file and decrypt it with the same settings as the malicious application. Running the script, it succesfully extracts the file. We then examine it with a simple "file" query.

```
ExtClass.dec: Dalvik dex file version 038
```

A dex file! This was likely going to be dynamically loaded by the dropper, and luckily we can examine it with the same tools as the dropper! We can run `d2j-dex2jar ExtClass.dec` to convert it to a jar and load it up in `jd-gui`. Luckily it decompiles beautifully! Unlike the APK, this has essentially a single class, `com.example.extlib.ExtClass`. This clearly contains the meat of the malware, including the following functions

```java
  public void changeWallpaper(Context paramContext) {
    wallpaperManager = WallpaperManager.getInstance(paramContext);
    Bitmap bitmap = BitmapFactory.decodeFile(this.filesDir + "/theme.jpg");
    try {
      wallpaperManager.setBitmap(bitmap);
    } catch (Exception wallpaperManager) {
      wallpaperManager.printStackTrace();
    } 
  }
  
  public void initLib(Context paramContext) {
    this.filesDir = paramContext.getFilesDir().getAbsolutePath();
    paramContext.registerReceiver(this, new IntentFilter(this.action2));
    paramContext.sendBroadcast(new Intent(this.action1));
  }
  
  public boolean isInfected() { return this.isInfected; }
  
  public void onReceive(Context paramContext, Intent paramIntent) {
    String str1 = paramIntent.getStringExtra(this.extraTag);
    String str2 = checkInf();
    if (str1 != null && str2 != null)
      this.isInfected = str1.equals(str2); 
    paramContext.unregisterReceiver(this);
  }
```

As you can see, it changes the wallpaper and takes notes on whether or not the device is succesfully infected. However, there is one additional function of incredible note to this challenge, `checkInf()`.

```java
  private String checkInf() {
    String str = this.filesDir + "/inf.enc";
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      SecretKeySpec secretKeySpec = new SecretKeySpec();
      this(messageDigest.digest("y3t_@n0th3r_p@ssw0rd".getBytes(StandardCharsets.UTF_8)), "AES");
      IvParameterSpec ivParameterSpec = new IvParameterSpec();
      this("@n0th3r_f1x3d_1v".getBytes(StandardCharsets.UTF_8));
      Cipher cipher = Cipher.getInstance("AES_256/CBC/PKCS7Padding");
      cipher.init(2, secretKeySpec, ivParameterSpec);
      return new String(cipher.doFinal(Files.readAllBytes(Paths.get(str, new String[0]))));
    } catch (Exception exception) {
      exception.printStackTrace();
      return null;
    } 
  }
```

This uses the same encryption scheme as before, with a different password and IV, to decrypt the other encrypted file! We can go ahead and decrypt that now using a modified version of the script from before.

```python
import hashlib

from Crypto.Cipher import AES


password = b"y3t_@n0th3r_p@ssw0rd"
IV = b"@n0th3r_f1x3d_1v"


m = hashlib.sha256()
m.update(password)
key = m.digest()

cipher = AES.new(key, AES.MODE_CBC, IV)

f = open("inf.enc", "rb")
ct = f.read()

pt = cipher.decrypt(ct)

f2 = open("inf.dec", "wb")

f2.write(pt)
```

We can then run `cat inf.dec` to get the flag!
```
THCon21{Dyn@m1c_c0d3_l0@d1ng_1s_$c@ry}
```

## Other interesting writeups.

I took a very static approach to this challenge as I don't like dealing with emulators, especially when potentially live malware is involved. In this case it was quite benign, but I tend to play it careful in this area. However, there was another writeup for this challenge that took a very dynamic approach! You can find it [over here](https://cryptax.github.io/2021/06/14/thcon.html).
