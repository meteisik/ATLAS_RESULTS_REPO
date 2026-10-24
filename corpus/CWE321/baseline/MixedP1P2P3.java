package cwe321.mixed;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MixedP1P2P3 {

    // Violation 1 (P01): key literal bound to a local, consumed directly.
    SecretKeySpec forgeInlineKey() {
        String inlineCrest = "k01_mixedbaseline";
        byte[] inlineSkein = inlineCrest.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec inlineSigil = new SecretKeySpec(inlineSkein, "AES");
        return inlineSigil;
    }

    // Violation 2 (P02): key literal returned by a same-class helper, then
    // consumed by an HMAC sink.
    Mac etchHelperMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String helperCourse = issueHelperEmblem();
        byte[] helperCord = helperCourse.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec helperSigil = new SecretKeySpec(helperCord, "HmacSHA256");
        Mac helperMac = Mac.getInstance("HmacSHA256");
        helperMac.init(helperSigil);
        return helperMac;
    }

    private String issueHelperEmblem() {
        return "k05_mixedbaseline";
    }

    // Violation 3 (P03): key assembled from two literal fragments through a
    // builder, so origin evidence is plural before refinement ever sees it.
    SecretKeySpec weaveFragmentKey() {
        StringBuilder fragmentMosaic = new StringBuilder();
        fragmentMosaic.append("k15_mi");
        fragmentMosaic.append("xedbaseline");
        String fragmentEmblem = fragmentMosaic.toString();
        byte[] fragmentCord = fragmentEmblem.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec fragmentSigil = new SecretKeySpec(fragmentCord, "AES");
        return fragmentSigil;
    }
}
