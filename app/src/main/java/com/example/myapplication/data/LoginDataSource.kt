package com.example.myapplication.data

import android.content.Context
import android.util.Log
import com.example.myapplication.data.model.LoggedInUser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.cert.CertificateFactory
import javax.net.ssl.*
import java.util.Scanner


import com.example.myapplication.R

class LoginDataSource(private val context: Context) {

    suspend fun login(username: String, password: String): Result<LoggedInUser> {
        return withContext(Dispatchers.IO) {
            try {
                Log.d("LoginDataSource", "Attempting to connect to server...")

                // Load cert and key
                val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                keyStore.load(null, null)
                context.resources.openRawResource(R.raw.cert).use { certInputStream ->
                    val certFactory = CertificateFactory.getInstance("X.509")
                    val cert = certFactory.generateCertificate(certInputStream)
                    keyStore.setCertificateEntry("cert", cert)
                }
                Log.d("LoginDataSource", "Loaded client certificate")
                context.resources.openRawResource(R.raw.key).use { keyInputStream ->
                    val keyFactory = KeyFactory.getInstance("RSA")
                    val keySpec = PKCS8EncodedKeySpec(keyInputStream.readBytes())
                    val privateKey = keyFactory.generatePrivate(keySpec)
                    keyStore.setKeyEntry("key", privateKey, null, arrayOf(keyStore.getCertificate("cert")))
                }
                val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                keyManagerFactory.init(keyStore, null)

                // Init SSL context
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(keyManagerFactory.keyManagers, null, SecureRandom())

                // Init SSL socket factory
                val sslSocketFactory: SSLSocketFactory = sslContext.socketFactory

                val socket: SSLSocket = sslSocketFactory.createSocket("192.168.137.139", 7778) as SSLSocket

                socket.startHandshake()

                val outputStream: OutputStream = socket.outputStream
                val inputStream: InputStream = socket.inputStream
                val scanner = Scanner(inputStream)

                // Send data
                val dataToSend = "STARTLOGIN${username}:${password}END"
                Log.d("LoginDataSource", "Sending data: $dataToSend")
                outputStream.write(dataToSend.toByteArray())
                outputStream.flush()

                // Get response
                val response = scanner.nextLine()
                Log.d("LoginDataSource", "Received response: $response")
                socket.close()

                if (response == "success") {
                    val fakeUser = LoggedInUser(java.util.UUID.randomUUID().toString(), "Jane Doe")
                    Result.Success(fakeUser)
                } else {
                    Result.Error(IOException("Error logging in"))
                }
            } catch (e: Throwable) {
                Log.e("LoginDataSource", "Error logging in", e)
                Result.Error(IOException("Error logging in", e))
            }
        }
    }

    fun logout() {
        // TODO: revoke authentication
    }
}

