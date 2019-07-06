package com.test.testoauth2jwt.controller;


import com.alibaba.fastjson.JSON;
import com.test.testoauth2jwt.dto.UserLoginDto;
import com.test.testoauth2jwt.po.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

@RestController
@RequestMapping("/user")
public class UserController {

    private final SecretKey key;

    public UserController() throws Exception {
        key = getSecretEncryptionKey();
    }

    @GetMapping("/login")
    public String login(UserLoginDto userLoginDto) throws Exception {
        String username = userLoginDto.getUsername();
        String password = userLoginDto.getPassword();
        if(username != null && !username.equals("slw")){
            throw new Exception("user doesn't exist");
        }
        if(password != null && !password.equals("123456")){
            throw new Exception("password in incorrect");
        }

        User user = new User();
        user.setUsername("slw");
        user.setMobile("12345678952");
        user.setEmail("aa@qq.com");
        user.setRole("admin");

        String s = JSON.toJSONString(user);

        byte[] bytes = encryptText(s, key);


        String s1 = Base64.getEncoder().encodeToString(bytes);

        return s1;
    }

    /**
     * gets the AES encryption key. In your actual programs, this should be safely
     * stored.
     * @return
     * @throws Exception
     */
    private SecretKey getSecretEncryptionKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return secKey;
    }

    /**
     * Encrypts plainText in AES using the secret key
     * @param plainText
     * @param secKey
     * @return
     * @throws Exception
     */
    public byte[] encryptText(String plainText,SecretKey secKey) throws Exception{
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }

}

