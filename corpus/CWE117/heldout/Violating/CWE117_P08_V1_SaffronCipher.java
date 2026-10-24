import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronCipher {

    public void handleSaffronCipher() {
        String data;
        data = System.getenv("SAFFRON_CIPHER_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronCipherSink()).logSaffronCipher(dataArray);
    }
}

class CWE117_P08_V1_SaffronCipherSink {
    public void logSaffronCipher(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + data);
    }
}
