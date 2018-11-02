import 'package:jose/src/jwk.dart';
import 'package:test/test.dart';

main() {
  group('JWK Examples from RFC7517', () {
    group('Example JSON Web Key Sets', () {
      test('Example Public Keys', () {
        var json = {
          "keys": [
            {
              "kty": "EC",
              "crv": "P-256",
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "use": "enc",
              "kid": "1"
            },
            {
              "kty": "RSA",
              "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
                  "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs"
                  "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2"
                  "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI"
                  "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb"
                  "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e": "AQAB",
              "alg": "RS256",
              "kid": "2011-04-29"
            }
          ]
        };

        var key1 = new JsonWebKey.fromJson(json["keys"][0]);

        expect(key1.keyType, "EC");
        expect(key1.keyId, "1");
        expect(key1.publicKeyUse, "enc");

        var key2 = new JsonWebKey.fromJson(json["keys"][1]);

        expect(key2.keyType, "RSA");
        expect(key2.keyId, "2011-04-29");
        expect(key2.algorithm, "RS256");

        var keySet = new JsonWebKeySet.fromJson(json);

        expect(keySet.keys[0], key1);
        expect(keySet.keys[1], key2);

        expect(keySet.toJson(), json);
      });

      test('Example Private Keys', () {
        var json = {
          "keys": [
            {
              "kty": "EC",
              "crv": "P-256",
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
              "use": "enc",
              "kid": "1"
            },
            {
              "kty": "RSA",
              "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
                  "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
                  "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
                  "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS"
                  "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"
                  "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e": "AQAB",
              "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9"
                  "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij"
                  "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d"
                  "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz"
                  "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz"
                  "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
              "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV"
                  "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV"
                  "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
              "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum"
                  "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx"
                  "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
              "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim"
                  "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu"
                  "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
              "dq": "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU"
                  "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9"
                  "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
              "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg"
                  "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx"
                  "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
              "alg": "RS256",
              "kid": "2011-04-29"
            }
          ]
        };

        var key1 = new JsonWebKey.fromJson(json["keys"][0]);

        expect(key1.keyType, "EC");
        expect(key1.keyId, "1");
        expect(key1.publicKeyUse, "enc");

        var key2 = new JsonWebKey.fromJson(json["keys"][1]);

        expect(key2.keyType, "RSA");
        expect(key2.keyId, "2011-04-29");
        expect(key2.algorithm, "RS256");

        var keySet = new JsonWebKeySet.fromJson(json);

        expect(keySet.keys[0], key1);
        expect(keySet.keys[1], key2);

        expect(keySet.toJson(), json);
      });

      test('Example Symmetric Keys', () {
        var json = {
          "keys": [
            {"kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg"},
            {
              "kty": "oct",
              "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
                  "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
              "kid": "HMAC key used in JWS spec Appendix A.1 example"
            }
          ]
        };

        var key1 = new JsonWebKey.fromJson(json["keys"][0]);

        expect(key1.keyType, "oct");
        expect(key1.algorithm, "A128KW");

        var key2 = new JsonWebKey.fromJson(json["keys"][1]);

        expect(key2.keyType, "oct");
        expect(key2.keyId, "HMAC key used in JWS spec Appendix A.1 example");

        var keySet = new JsonWebKeySet.fromJson(json);

        expect(keySet.keys[0], key1);
        expect(keySet.keys[1], key2);

        expect(keySet.toJson(), json);
      });
    });

    test('Example Use of "x5c" (X.509 Certificate Chain) Parameter', () {
      var json = {
        "kty": "RSA",
        "use": "sig",
        "kid": "1b94c",
        "n": "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08"
            "PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q"
            "u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"
            "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH"
            "MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv"
            "VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
        "e": "AQAB",
        "x5c": [
          "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB"
              "gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD"
              "VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1"
              "wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg"
              "NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV"
              "QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w"
              "YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH"
              "YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66"
              "s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6"
              "SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn"
              "fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq"
              "PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk"
              "aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA"
              "QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL"
              "+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1"
              "zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL"
              "2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo"
              "4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq"
              "gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="
        ]
      };

      var key = new JsonWebKey.fromJson(json);

      expect(key.keyType, "RSA");

      expect(key.toJson(), json);
    }, skip: "X.509 not implemented");
  });
}
