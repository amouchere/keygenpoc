package com.amouchere.keygenpoc;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class KeyGenTest {

    private static final String OUTPUT = "target/keyfiles";
    private static final String KEY_COMMENT = "KEY_COMMENT";

    @BeforeClass
    public void clean() throws IOException {
        FileUtils.deleteDirectory(new File(OUTPUT));
    }

    @Test
    public void test() {
        try {
            String keyFilename = OUTPUT + File.separatorChar + "id_dsa";

            // only create keys if they don't exist
            File privateKeyFile = new File(keyFilename);
            if (privateKeyFile.exists()) {
                log.error("keyfile exists, will not create new key: {}", privateKeyFile);
                return;
            }

            // create dirs
            File dirs = new File(OUTPUT);
            if (!dirs.exists() && !dirs.mkdirs()) {
                throw new IOException("could not create dir(s): " + OUTPUT);
            }

            // generate keys
            log.debug("generating keys in dir: {}", dirs);
            JSch jsch = new JSch();
            KeyPair kpair = KeyPair.genKeyPair(jsch, KeyPair.RSA);
            kpair.writePrivateKey(keyFilename);
            kpair.writePublicKey(keyFilename + ".pub", KEY_COMMENT);
            kpair.dispose();
        } catch (Exception e) {
            String errMsg = "Failed to generate SSH keys";
            log.error(errMsg, e);
            throw new RuntimeException(errMsg, e);
        }

    }

    @Test
    public void test2() {
        KeyPair pair = null;
        try {
            pair = KeyPair.genKeyPair(new JSch(), KeyPair.RSA);
        } catch (JSchException e) {
            String errMsg = "Failed to generate SSH keys";
            log.error(errMsg, e);
            throw new RuntimeException(errMsg, e);
        }

        ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
        pair.writePrivateKey(privateKey);
        ByteArrayOutputStream publicKey = new ByteArrayOutputStream();
        pair.writePublicKey(publicKey, KEY_COMMENT);
        log.info("---------------");
        log.info("Private KEY \n {}", new String(privateKey.toByteArray()));
        log.info("---------------");
        log.info("public KEY \n {}", new String(publicKey.toByteArray()));
        log.info("---------------");
    }

}
