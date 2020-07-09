package com.lidaye.rsa.demorsa;

public class App {
    public static void main(String[] args) throws Exception {
        String str = "李大爷";
        RSAUtil rsaUtils = new RSAUtil();
        rsaUtils.initKey(
                "src/main/resources/lidaye_private.pem",
                "src/main/resources/lidaye_public.pem"
        );

        String sign = rsaUtils.sign(str);

        // 生成签名
        System.out.println(sign);
        // 验签
        System.out.println(rsaUtils.verify(str, sign));
    }
}
