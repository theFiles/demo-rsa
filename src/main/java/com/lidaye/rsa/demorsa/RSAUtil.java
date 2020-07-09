package com.lidaye.rsa.demorsa;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

/**
 * RSA签名验签
 * @author lidaye
 */
public class RSAUtil {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    // 加密block需要预留11字节
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final int KEYBIT = 2048;
    public static final int RESERVEBYTES = 11;
    private KeyFactory keyFactory;

    private int encryptBlock;
    private int decryptBlock;

    /** 公钥私钥 **/
    private static PrivateKey localPrivKey;
    private static PublicKey peerPubKey;

    /** 开始接受前缀 **/
    private static final String KEY_BEGIN_PREFIX = "-----BEGIN";
    private static final String KEY_END_PREFIX = "-----END";

    /** base64加解密对象 **/
    private static BASE64Encoder base64Encoder;
    private static BASE64Decoder base64Decoder;
    static{
        base64Encoder = new BASE64Encoder();
        base64Decoder = new BASE64Decoder();
    }


    public RSAUtil() throws Exception {
        keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 256 bytes
        decryptBlock = KEYBIT / 8;
        // 245 bytes
        encryptBlock = decryptBlock - RESERVEBYTES;
    }

    /**
     * 签名
     *
     * @param plaintext             要签名的字符串
     * @return 返回签名后的结果
     * @throws Exception            异常
     */
    public String sign(String plaintext) throws Exception {
        String signBase64Str = "";
        // 载入秘钥
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(localPrivKey);
        signature.update(plaintext.getBytes("GBK"));
        // base64编码
        signBase64Str = base64Encoder.encode(signature.sign());

        return signBase64Str;
    }

    /**
     * 验签
     *
     * @param plaintext                 验签的字符串
     * @param signBase64Str             验签的签名
     * @return 验证成功或失败
     * @throws UnsupportedEncodingException 异常
     */
    public boolean verify(String plaintext, String signBase64Str) throws Exception {
        boolean isValid = false;
        // 载入公钥
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(peerPubKey);
        signature.update(plaintext.getBytes("GBK"));
        // 执行验签函数及base64解码
        isValid = signature.verify(base64Decoder.decodeBuffer(signBase64Str));

        return isValid;
    }

    /**
     * 加密
     *
     * @param str_data          加密字符串
     * @return 加密后的密文
     * @throws UnsupportedEncodingException 异常
     */
    public String encrypt(String str_data) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DeflaterOutputStream zos = new DeflaterOutputStream(bos);
        zos.write(str_data.getBytes("GBK"));
        zos.close();
        byte[] data = bos.toByteArray();
        // 计算分段加密的block数 (向上取整)
        int nBlock = (data.length / encryptBlock);
        // 余数非0block数再加1
        if ((data.length % encryptBlock) != 0)
        {
            nBlock += 1;
        }
        // 输出buffer, 大小为nBlock个decryptBlock
        ByteArrayOutputStream outbuf = new ByteArrayOutputStream(nBlock * decryptBlock);
        // 分段加密
        writeToStream(data,Cipher.ENCRYPT_MODE,peerPubKey,outbuf);

        // ciphertext
        return base64Encoder.encode(outbuf.toByteArray());
    }

    /**
     * 解密
     *
     * @param cryptedBase64Str          解密密文
     * @return
     */
    public String decrypt(String cryptedBase64Str) throws Exception {
        // 转换得到字节流
        byte[] data = base64Decoder.decodeBuffer(cryptedBase64Str);
        // 计算分段解密的block数 (理论上应该能整除)
        int nBlock = (data.length / decryptBlock);
        // 输出buffer, , 大小为nBlock个encryptBlock
        ByteArrayOutputStream outbuf = new ByteArrayOutputStream(nBlock * encryptBlock);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, localPrivKey);
        // 分段解密
        writeToStream(data,Cipher.DECRYPT_MODE,localPrivKey,outbuf);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        InflaterOutputStream zos = new InflaterOutputStream(bos);
        zos.write(outbuf.toByteArray());
        zos.close();

        return new String(bos.toByteArray(), "GBK");
    }

    /**
     * 解析内容并写入到流
     * @param data              内容字节集
     * @param cipherMode        加密或解密
     * @param key               秘钥
     * @param stream            流容器
     * @throws Exception
     */
    private void writeToStream(byte[] data, int cipherMode, Key key, ByteArrayOutputStream stream) throws Exception {
        int len = data.length;

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(cipherMode, key);

        for (int offset = 0; offset < len; offset += decryptBlock) {
            // block大小: decryptBlock 或 剩余字节数
            int inputLen = (len - offset);
            if (inputLen > decryptBlock) {
                inputLen = decryptBlock;
            }
            // 得到分段结果
            byte[] decryptedBlock = cipher.doFinal(data, offset, inputLen);
            // 追加结果到输出buffer中
            stream.write(decryptedBlock);
        }
        // ---写完成后，需要刷新缓冲区，并且关闭缓冲
        stream.flush();
        stream.close();
    }

    /**
     * 初始化自己的私钥 `openssl genrsa -out rsa_2048.key 2048` #指定生成的密钥的位数: 2048
     * `openssl pkcs8 -topk8 -inform PEM -in rsa_2048.key -outform PEM -nocrypt
     * -out pkcs8.txt` #for Java 转换成PKCS#8编码 `openssl rsa -in rsa_2048.key
     * -pubout -out rsa_2048_pub.key` #导出pubkey
     *
     * @param privKeyPath           私钥路径
     * @param pubKeyPath            公钥路径
     */
    public void initKey(String privKeyPath, String pubKeyPath) throws Exception {
        // 读取私钥
        localPrivKey = initPrivateKey(privKeyPath);
        // 读取公钥
        peerPubKey = initPublicKey(pubKeyPath);
    }

    /**
     * 读取私钥
     */
    private static PrivateKey initPrivateKey(String privKeyPath) throws Exception {
        byte[] keybyte = readKey(privKeyPath);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybyte);
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(keySpec);
    }

    /**
     * 读取公钥
     */
    private static PublicKey initPublicKey(String pubKeyPath) throws Exception {
        byte[] keybyte = readKey(pubKeyPath);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keybyte);
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(keySpec);
    }

    /**
     * 读取秘钥
     * @param keyPath           秘钥路径
     * @return
     * @throws Exception
     */
    private static byte[] readKey(String keyPath) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(keyPath));
        StringBuffer key = new StringBuffer();

        String s = br.readLine();
        if(s.startsWith(KEY_BEGIN_PREFIX)){ s = br.readLine(); }

        while (!Objects.isNull(s) && !s.startsWith(KEY_END_PREFIX)) {
            key.append(s + "\r");
            s = br.readLine();
        }
        BASE64Decoder base64decoder = new BASE64Decoder();
        return base64decoder.decodeBuffer(key.toString());
    }
}
