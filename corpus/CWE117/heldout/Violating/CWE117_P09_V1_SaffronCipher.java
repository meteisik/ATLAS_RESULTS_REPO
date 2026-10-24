import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronCipher {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronCipher() {
        String data;
        data = System.getenv("SAFFRON_CIPHER_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronCipherSink()).logSaffronCipher(dataContainer);
    }
}

class CWE117_P09_V1_SaffronCipherSink {
    public void logSaffronCipher(CWE117_P09_V1_SaffronCipher.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronCipherLogger = Logger.getLogger("saffronCipher.audit");
        saffronCipherLogger.info("Login attempt for user " + data);
    }
}
