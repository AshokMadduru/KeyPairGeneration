package com.shok.eckeypaigeneration;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by Ashok on 30/9/18.
 */
public class KeyUtils {
  private final String KEY_ALIAS = "androidKey";
  private final String ANDROID_KEY_STORE = "AndroidKeyStore";
  private final String EC_CURVE_SPEC = "secp256r1";
  private final String SIGNING_ALG = "SHA256withECDSA";

  private KeyStore keyStore;
  private ECPublicKey publicKey;

  KeyUtils() {
  }

  /**
   * Generates EC keypair
   */
  private void generateKeyPairs() {
    KeyPairGenerator generator = null;
    try {
      generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE);
      try {
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN).setAlgorithmParameterSpec(
            new ECGenParameterSpec(EC_CURVE_SPEC)).build();
        generator.initialize(keyGenParameterSpec);
      } catch (InvalidAlgorithmParameterException e) {
        e.printStackTrace();
      }
      generator.generateKeyPair();
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      e.printStackTrace();
    }
  }

  /**
   *
   * @param message message to be encoded
   * @return Base64 encoded message with url safe
   */
  public String signMessage(String message) {
    try {
      Signature signature = Signature.getInstance(SIGNING_ALG);
      getKeyStoreInstance();
      try {
        signature.initSign(getPrivateKey());
        signature.update(message.getBytes());
        byte[] sigBytes = signature.sign();
        return Base64.encodeToString(sigBytes,
            Base64.CRLF | Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
      } catch (InvalidKeyException | SignatureException e) {
        e.printStackTrace();
      }
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return "";
  }

  /**
   *
   * @return Base64 encoded x
   */
  public String getX() {
    ECPublicKey publicKey = getPublicKey();
    if (publicKey != null) {
      return Base64.encodeToString(publicKey.getW().getAffineX().toByteArray(), Base64.CRLF);
    }
    return "";
  }

  /**
   *
   * @return Base64 encoded y
   */
  public String getY() {
    ECPublicKey publicKey = getPublicKey();
    if (publicKey != null) {
      return Base64.encodeToString(publicKey.getW().getAffineY().toByteArray(), Base64.CRLF);
    }
    return "";
  }

  /**
   * @return Private Key
   */
  private PrivateKey getPrivateKey() {
    if (!isKeyExists()) {
      generateKeyPairs();
    }
    KeyStore keyStore = getKeyStoreInstance();
    if (keyStore == null) {
      return null;
    }
    try {
      return (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * @return PublicKey
   */
  public ECPublicKey getPublicKey() {
    if (!isKeyExists()) {
      generateKeyPairs();
    }
    KeyStore keyStore = getKeyStoreInstance();
    if (publicKey == null && keyStore != null) {
      try {
        publicKey = (ECPublicKey) keyStore.getCertificate(KEY_ALIAS).getPublicKey();
      } catch (KeyStoreException e) {
        e.printStackTrace();
      }
    }
    return publicKey;
  }

  /**
   * @return true if key exists with the given key alias.
   */
  private boolean isKeyExists() {
    KeyStore keyStore = getKeyStoreInstance();
    if (keyStore != null) {
      try {
        return  keyStore.containsAlias(KEY_ALIAS);
      } catch (KeyStoreException e) {
        e.printStackTrace();
      }
    }
    return false;
  }

  /**
   * Generates keystore instance
   */
  private KeyStore getKeyStoreInstance() {
    if (keyStore == null) {
      try {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
      } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
        e.printStackTrace();
      }
    }
    return keyStore;
  }
}
