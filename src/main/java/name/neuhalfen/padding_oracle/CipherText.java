package name.neuhalfen.padding_oracle;

import sun.misc.BASE64Encoder;

public final class CipherText {
    public final byte[] iv;
    public final byte[] ciphertext;
    public final byte[] hmac;

    public CipherText(byte[] iv, byte[] ciphertext, byte[] hmac) {
        this.iv = new byte[iv.length];
        System.arraycopy(iv, 0, this.iv, 0, iv.length);

        this.ciphertext = new byte[ciphertext.length];
        System.arraycopy(ciphertext, 0, this.ciphertext, 0, ciphertext.length);

        this.hmac = new byte[hmac.length];
        System.arraycopy(hmac, 0, this.hmac, 0, hmac.length);
    }

    @Override
    public Object clone()  {
        return new CipherText(this.iv, this.ciphertext, this.hmac);
    }


    @Override
    public String toString() {
      BASE64Encoder base64 =  new BASE64Encoder();
      return  String.format("{ iv:'%s', ciphertext:'%s', hmac:'%s' }", base64.encode(iv), base64.encode(ciphertext), base64.encode(hmac) );
    }
}
