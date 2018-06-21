package com.metamx.tranquility.security

import java.io.FileInputStream
import java.io.IOException
import java.security.{NoSuchAlgorithmException, KeyStoreException, KeyManagementException, KeyStore}
import java.security.cert.CertificateException
import javax.net.ssl.{TrustManagerFactory, SSLContext}

import com.metamx.common.scala.Logging
import com.metamx.tranquility.config.PropertiesBasedConfig

object SSLContextMaker extends Logging
{
  def createSSLContextOption(generalConfig: PropertiesBasedConfig): Option[SSLContext] = {
    if (!generalConfig.tlsEnable) {
      log.info("TLS is not enabled, skipping SSLContext creation.")
      return Option.empty[SSLContext]
    }

    log.info("TLS is enabled, creating SSLContext.")

    var sslContext: SSLContext = null
    try {
      sslContext = SSLContext.getInstance(generalConfig.tlsProtocol)
      var keyStore = KeyStore.getInstance(generalConfig.tlsTrustStoreType)
      keyStore.load(
        new FileInputStream(generalConfig.tlsTrustStorePath),
        generalConfig.tlsTrustStorePassword.toCharArray
      )
      var trustManagerFactory = TrustManagerFactory.getInstance(generalConfig.tlsTrustStoreAlgorithm)
      trustManagerFactory.init(keyStore)
      sslContext.init(null, trustManagerFactory.getTrustManagers, null)
    }
    catch {
      case ex@(_: CertificateException |
               _: KeyManagementException |
               _: IOException |
               _: KeyStoreException |
               _: NoSuchAlgorithmException) =>
        throw new RuntimeException(ex)
    }

    Option.apply(sslContext)
  }
}
