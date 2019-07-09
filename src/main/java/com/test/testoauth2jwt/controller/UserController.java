package com.test.testoauth2jwt.controller;


import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.test.testoauth2jwt.dto.UserLoginDto;
import com.test.testoauth2jwt.po.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@RestController
@RequestMapping("/user")
public class UserController {

    private final SecretKey key;

    public UserController() throws Exception {
        key = getSecretEncryptionKey();
    }

    public SecretKey getKey() {
        return key;
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

        //对称
//        byte[] bytes = encryptText(s, key);
//
//
//        String s1 = Base64.getEncoder().encodeToString(bytes);

        //JWT
        Date date = new Date();
        long time = date.getTime();
        Long expiresat = time+7200*1000;
        Algorithm algorithm = Algorithm.HMAC256("slwsec");//秘钥  可以自己填
        String token = JWT.create()
                .withIssuer("slwsrv")//签发者
                .withSubject("slw")//用户名  userID  都可以
                .withIssuedAt(new Date())//签发时间
                .withExpiresAt(new Date(expiresat))//到期时间
                .sign(algorithm);
        String s1 = Base64.getEncoder().encodeToString(token.getBytes());
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

    /**
     * Decrypts encrypted byte array using the key used for encryption.
     * @param byteCipherText
     * @param secKey
     * @return
     * @throws Exception
     */
    public String decryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
        return new String(bytePlainText);
    }

    @GetMapping("/synhello")
    public DecodedJWT synhello(String token, String name) throws Exception {
        //由于+号在url传输的时候会自动转换成空格所以需要转换一下  +属于非法字符
        token = token.replaceAll(" ","+");
        //对称
//        byte[] decode = Base64.getDecoder().decode(token);
//        String s = decryptText(decode, key);

        //JWT
        Algorithm algorithm = Algorithm.HMAC256("slwsec");
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("slwsrv")
                .build(); //Reusable verifier instance
        DecodedJWT jwt = verifier.verify(token);
        return jwt;
    }

    @GetMapping("/synhello2")//RequestAttribute 后面可以写key值  如果不写默认变量名称
    public String synhello2(@RequestAttribute String username) throws Exception {

        return username;
    }

}

