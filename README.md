# Chattha Boost SMM Panel — No Email Verification

This version keeps the previous core features but removes only email verification and SMTP.

## Registration
Name + email + password creates the account immediately.

Important: the app validates email format only. It cannot guarantee that a mailbox really exists without sending a verification email.

## Features kept
- Register/login
- Customer dashboard
- Balance system
- Orders and order status
- Quantity-based prices
- Insufficient balance blocks order
- Transaction ID required
- Payment screenshot required
- Payment requests automatically Pending
- Admin approves/rejects payments
- Approved amount adds to customer balance
- Services, prices, offers, orders, users and payments
- Easypaisa instructions for Shahzaib Hussain / 03476277164
- WhatsApp support 03406742924

## Run
npm install
Copy .env.example to .env and set JWT_SECRET, ADMIN_EMAIL and ADMIN_PASSWORD.
npm start
