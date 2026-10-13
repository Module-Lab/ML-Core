import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Автономный гейт витрины: проверяет подписанный модуль ПО КОНТЕНТУ СТОРА, без доступа к исходникам ядра.
 * Чистая JCA (ECDSA P-256 / SHA256withECDSA), компилируется голым {@code javac} в CI публичного репа.
 *
 * <pre>java VerifyModule &lt;jarFile&gt; &lt;storeDir&gt;</pre>
 *
 * Проверяет по цепочке доверия (так же, как клиент, но корень тут — публичный {@code store/keys/trust.json}):
 *   1. сайдкар {@code <jar>.modlex.json} есть, {@code sha256} совпал с файлом (иначе подмена);
 *   2. keyId/sha256 НЕ в revoked (файлы {@code store/revoked/keys|hashes});
 *   3. автор заверён: есть {@code store/authors/&lt;keyId&gt;/cert.json};
 *   4. подпись jar проходит публичным ключом автора;
 *   5. rootSignature сертификата автора проходит публичному корню из trust.json.
 * Всё зелёное -&gt; печатает RESULT=VERIFIED, код 0. Иначе RESULT=REJECT..., код 1.
 */
public final class VerifyModule {

    public static void main(String[] a) throws Exception {
        if (a.length < 2) {
            fail("usage: VerifyModule <jarFile> <storeDir>");
        }
        File jar = new File(a[0]);
        File store = new File(a[1]);
        if (!jar.isFile()) {
            fail("jar not found: " + jar);
        }

        File side = new File(jar.getParentFile(), jar.getName() + ".modlex.json");
        if (!side.isFile()) {
            fail("no sidecar " + side.getName() + " -> UNSIGNED");
        }
        String s = read(side);
        String id = json(s, "id");
        String version = json(s, "version");
        String wantHash = json(s, "sha256");
        String sig = json(s, "signature");
        String keyId = json(s, "keyId");
        String alg = json(s, "alg");

        byte[] bytes = Files.readAllBytes(jar.toPath());
        String hash = sha256Hex(bytes);
        System.out.println("module  = " + id + " " + version);
        System.out.println("keyId   = " + keyId);
        System.out.println("sha256  = " + hash + (hash.equalsIgnoreCase(wantHash) ? " (match)" : " (MISMATCH)"));
        if (!hash.equalsIgnoreCase(wantHash)) {
            fail("HASH_MISMATCH: файл не совпадает с сайдкаром");
        }

        if (new File(new File(store, "revoked/keys"), keyId + ".json").isFile()) {
            fail("REVOKED key: " + keyId);
        }
        if (new File(new File(store, "revoked/hashes"), hash + ".json").isFile()) {
            fail("REVOKED hash: " + hash);
        }

        File trust = new File(new File(store, "keys"), "trust.json");
        if (!trust.isFile()) {
            fail("no store/keys/trust.json");
        }
        String rootPub = json(read(trust), "rootPublicKey");

        File cert = new File(new File(new File(store, "authors"), keyId), "cert.json");
        if (!cert.isFile()) {
            fail("UNKNOWN_KEY: автор не заверён (нет authors/" + keyId + "/cert.json)");
        }
        String cs = read(cert);
        String authorPub = json(cs, "publicKey");
        String rootSig = json(cs, "rootSignature");

        String jca = jca(alg);
        if (!verify(bytes, sig, authorPub, jca)) {
            fail("BAD_SIGNATURE: подпись jar не проходит ключом автора");
        }
        byte[] pubDer = Base64.getMimeDecoder().decode(authorPub);
        if (!verify(pubDer, rootSig, rootPub, jca)) {
            fail("BAD_CERT: rootSignature не проходит публичному корню из trust.json");
        }
        System.out.println("RESULT  = VERIFIED");
    }

    private static String jca(String alg) {
        String x = alg == null ? "" : alg.trim();
        if (x.isEmpty() || x.equalsIgnoreCase("ECDSA-P256-SHA256") || x.equalsIgnoreCase("SHA256withECDSA")) {
            return "SHA256withECDSA";
        }
        fail("unsupported alg: " + alg);
        return null;
    }

    private static boolean verify(byte[] data, String sigB64, String pubB64, String jca) throws Exception {
        PublicKey pub = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(Base64.getMimeDecoder().decode(pubB64)));
        Signature v = Signature.getInstance(jca);
        v.initVerify(pub);
        v.update(data);
        return v.verify(Base64.getMimeDecoder().decode(sigB64));
    }

    private static String sha256Hex(byte[] b) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder sb = new StringBuilder(h.length * 2);
        for (byte x : h) {
            sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        }
        return sb.toString();
    }

    private static String read(File f) throws Exception {
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim();
    }

    /** Вытащить значение плоского поля "key":"value" (base64/hex/ascii — без внутренних кавычек). */
    private static String json(String src, String key) {
        String k = "\"" + key + "\"";
        int i = src.indexOf(k);
        if (i < 0) {
            return "";
        }
        int c = src.indexOf(':', i + k.length());
        int q1 = src.indexOf('"', c + 1);
        int q2 = src.indexOf('"', q1 + 1);
        return (q1 < 0 || q2 < 0) ? "" : src.substring(q1 + 1, q2);
    }

    private static void fail(String m) {
        System.out.println("RESULT  = REJECT: " + m);
        System.exit(1);
    }

    private VerifyModule() {
    }
}
