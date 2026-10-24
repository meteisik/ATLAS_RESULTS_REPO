import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronCipherSafe {

    public void handleSaffronCipher() {
        String data;
        data = System.getenv("SAFFRON_CIPHER_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronCipherSafeSink()).logSaffronCipher(dataArray);
    }
}

class CWE117_P08_V1_SaffronCipherSafeSink {
    public void logSaffronCipher(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
