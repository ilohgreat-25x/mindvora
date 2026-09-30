# Frontend bug fixes

## Round 5
1. Google sign-in: the security policy (vercel.json) blocked apis.google.com and the Firebase login frame (*.firebaseapp.com, accounts.google.com). Google sign-in could not start. Fixed.
2. Google sign-in: the login listener could run before the profile was saved and create it with emailVerified:false, so Google users were sent to the email-code screen. Google users are now always treated as verified, and old Google profiles are corrected when they sign in.
3. Google sign-in: if the popup is blocked, it switches to redirect sign-in automatically. Inside Instagram, Facebook or WhatsApp browsers it tells the user to open Chrome or Safari. In the Android/iOS app it uses the native Google sign-in plugin.
4. Clear messages for every Firebase sign-in error code, instead of raw Firebase text.
5. Trivia: loads live questions from the server first, then directly from Open Trivia DB (handles its rate limit), then the built-in questions. Jokes and Riddles stay built-in. Scoring is unchanged.
6. News: loads live news from the server with category buttons (World, Nigeria, Africa, Business, Tech, Sport). The old public-proxy method is kept as a backup.

## Round 4
1. ARIA now asks the server's real AI (app + general questions); if the server is asleep or offline it falls back to the built-in answers, so it never goes silent.
2. Fixed attached-image messages in ARIA showing raw HTML code.

## Round 3
1. Voice and video calls in Messages (calls.js): 📞 / 🎥 buttons in each chat, ringing screen, accept/decline, mute, camera on/off, switch camera, speaker, call timer, auto-reconnect when switching Wi-Fi ↔ data. The old Firestore call code was never connected to any button.
2. Real-time socket: reconnects forever (fast backoff), instantly on network return / app reopen.
3. Push notifications when the app is closed: two service workers were fighting over the same scope (firebase-messaging-sw.js replaced sw.js), so push kept breaking. Now one worker (sw.js) does cache + push; tokens saved per device (fcmTokens); tapping a notification opens the right screen; permission asked with a "Turn on" banner (required on iPhone). Native app push via Capacitor.
4. Storage: the service worker cached every file forever (including images/videos). Now only the site's own small files, max 40 entries; old caches deleted; ringtone is generated (no audio file).
5. Responsive layout (responsive.css): phone / tablet / desktop breakpoints, safe areas for notched phones, Messages switch between list and chat on phones with a back button, 16px inputs so iPhone doesn't zoom, full-screen call UI.
6. Update check (app-update.js): "Update required" / "Update available" screens driven by the backend; Paystack public key (test/live) loaded from the server.
7. App description rewritten in plain language (index.html, manifest.json).

## Round 2
1. Payments: premium, badge, tips, gifts, airtime and data no longer write isPremium / isVerified / earnings / gifts / topups from the browser. After Paystack succeeds, the app calls the backend to confirm, and the backend grants the feature. Crypto polling is read-only.
2. Firestore rules: isPremium, plan, isVerified, tips (and the premium/verified metadata) can only be changed by the backend. New accounts can't start premium/verified/with money. gifts/topups can't be created by clients.
3. Data bundles cost ₦0: prices were read with parseInt("0.10") = 0. Now parseFloat, and kobo amounts are rounded.
4. The default premium plan was priced 2000 (USD!) instead of $5; the crypto badge charged $30 while the button said $25.
5. Airtime/data check for a Nigerian network + valid number BEFORE charging (previously you could pay and get nothing).
6. Can't tip / gift yourself; tip max $1000, airtime max $100 (matches the server).
7. If the Paystack popup can't load, hosted checkout is used and the payment is confirmed when the user returns.
8. reCAPTCHA: a 10s timeout and a guard against execute() throwing — signup no longer hangs forever with a bad key/domain.
9. Signup: if the code email fails, the code screen still shows (with Resend). Before, the user was sent back to the form and retrying said "email already in use".
10. Code screen: "No code sent yet" is no longer shown as "expired"; a code sent within the last 60s is accepted instead of erroring.
11. Referral notification used `uid` instead of `toUid` (never shown).
12. All backend calls go through mvApi(): login token attached, 70s timeout for Render cold starts, no crash on non-JSON replies.
13. Removed the stale backend copy (server.js, CRLF/, api/, _deprecated/, package.json, package-lock.json). The site is purely static.

## Round 1
1. Crypto invoice field names didn't match the backend.
2. Profile updates were denied once an account had earnings.
3. Crypto payment status updates were always denied (superseded by round 2).

## You must do
- Deploy the rules: firebase deploy --only firestore:rules
- In the reCAPTCHA admin, add every domain the site runs on (see README note in the chat).
