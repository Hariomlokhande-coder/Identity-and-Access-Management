package com.example.iam.client;

public enum ClientType {
    /** Browser or mobile app: cannot keep a secret, so PKCE is mandatory. */
    PUBLIC,

    /** Server-side app: authenticates with a client secret. */
    CONFIDENTIAL
}