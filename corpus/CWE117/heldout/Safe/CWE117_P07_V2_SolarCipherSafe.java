import java.util.logging.Logger;

public class CWE117_P07_V2_SolarCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSolarCipher() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = (new CWE117_P07_V2_SolarCipherSafeSource()).readSolarCipher();
        } else {
            data = null;
        }
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SolarCipherSafeSource {
    public String readSolarCipher() {
        String data;
        data = System.getenv("SOLAR_CIPHER_USER");
        return data;
    }
}
