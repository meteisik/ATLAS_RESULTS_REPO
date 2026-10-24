package cwe117.mixed;

import java.util.logging.Logger;

public class MixedCWE117P1P2P3 {

    // Violation 1 (P01): environment value logged in the same method.
    public void recordDirectLogin() {
        String data;
        data = System.getenv("MIXED_DIRECT_USER");
        Logger directLogger = Logger.getLogger("mixed.direct.audit");
        directLogger.info("Login attempt for user " + data);
    }

    // Violation 2 (P02): environment value copied through a second local
    // inside a nested block, then logged from a second block.
    public void recordCopiedLogin() {
        String dataCopy;
        {
            String data;
            data = System.getenv("MIXED_COPIED_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger copiedLogger = Logger.getLogger("mixed.copied.audit");
            copiedLogger.info("Login attempt for user " + data);
        }
    }

    // Violation 3 (P03): environment value passed as an argument to a private
    // sink method of the same class.
    public void recordDelegatedLogin() {
        String data;
        data = System.getenv("MIXED_DELEGATED_USER");
        logDelegatedLogin(data);
    }

    private void logDelegatedLogin(String data) {
        Logger delegatedLogger = Logger.getLogger("mixed.delegated.audit");
        delegatedLogger.info("Login attempt for user " + data);
    }

    // Safe (P01 safe twin): same flow as violation 1, but CR and LF are
    // stripped by a sanitizer before the value reaches the log call.
    public void recordSanitizedLogin() {
        String data;
        data = System.getenv("MIXED_SANITIZED_USER");
        Logger sanitizedLogger = Logger.getLogger("mixed.sanitized.audit");
        sanitizedLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
