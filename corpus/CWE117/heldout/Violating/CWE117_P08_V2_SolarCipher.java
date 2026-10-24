import java.util.logging.Logger;

public class CWE117_P08_V2_SolarCipher {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSolarCipher() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SOLAR_CIPHER_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SolarCipherSink()).logSolarCipher(dataArray);
    }
}

class CWE117_P08_V2_SolarCipherSink {
    public void logSolarCipher(String[] dataArray) {
        String data = dataArray[2];
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + data);
    }
}
