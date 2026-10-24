import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrCipher {

    public void handleZephyrCipher() {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_CIPHER_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrCipherSink()).logZephyrCipher(dataArray);
    }
}

class CWE117_P08_V2_ZephyrCipherSink {
    public void logZephyrCipher(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + data);
    }
}
