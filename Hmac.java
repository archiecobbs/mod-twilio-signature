import java.io.*;
import java.net.*;
import java.nio.charset.*;
import java.nio.charset.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Hmac {

    public static final String ALGORITHM = "HmacSHA1";

    //
    // Ussage:
    //  cat payload | java Hmac auth-token URL
    //
    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws Exception {

        // Initialize HMAC
        String key = args[0];
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(signingKey);

        // Hash URL, etc
        for (int i = 1; i < args.length; i++)
            digest(mac, args[i]);

        // Hash payload
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        for (int r; (r = System.in.read()) != -1; )
            buf.write(r & 0xff);
        byte[] data = buf.toByteArray();
        String s = new String(data, StandardCharsets.UTF_8);
        String s2 = URLDecoder.decode(s);
        TreeMap<String, String> params = new TreeMap<>();
        for (String nvp : s2.split("&")) {
            int equal = nvp.indexOf('=');
            String name = nvp.substring(0, equal);
            String value = nvp.substring(equal + 1);
            params.put(name, value);
        }
        params.forEach((name, value) -> {
            digest(mac, name);
            digest(mac, value);
        });

        // Finalize
        byte[] hmacBytes = mac.doFinal();

        // Print result
        for (int i = 0; i < hmacBytes.length; i++)
            System.out.print(String.format("%02x", hmacBytes[i] & 0xff));
        System.out.println(String.format(" -> %s", Base64.getEncoder().encodeToString(hmacBytes)));
    }

    private static void digest(Mac mac, String value) {
        System.err.println(String.format("digest: \"%s\"", value));
        mac.update(value.getBytes(StandardCharsets.UTF_8));
    }
}
