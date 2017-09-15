/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 *
 * @author asyd
 */
class KeyManager {

    KeyPair createRSA(Integer keySize) {
        KeyPairGenerator kpg;
        KeyPair kp = null;
        
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            kp = kpg.genKeyPair();
            
        } catch (Exception e) {
            // ignore
        }

        return kp;
    }
}
