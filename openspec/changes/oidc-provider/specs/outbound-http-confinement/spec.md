# Spec Delta

## ADDED Requirements

### Requirement: A client can be copied to follow no redirect
A consumer SHALL be able to take a confined client and get a copy that follows no redirect, whatever the original allows. The copy SHALL keep the original's scheme and origin rules, and the original SHALL be unchanged. A redirect answered to the copy SHALL be a refusal, and its target SHALL NOT be requested.

#### Scenario: A credential is not sent again
- **WHEN** the copy sends a form POST carrying a credential to `https://rp.example.com/logout`, and the answer is `307` to the same origin
- **THEN** no second request is sent, and the POST is refused

#### Scenario: The original still follows
- **WHEN** a client allowing redirects is copied, and the original then requests a URL answering `302` on the same origin
- **THEN** the original follows it

### Requirement: A form POST can be judged by its status alone
A consumer SHALL be able to send a form POST and receive the response status without the body being read. The body's size SHALL NOT affect the answer, and the connection SHALL be released at once.

#### Scenario: Oversized body
- **WHEN** a form POST judged by status alone is answered `200`, with a body larger than the client's response bound
- **THEN** the caller receives status `200` and no error
