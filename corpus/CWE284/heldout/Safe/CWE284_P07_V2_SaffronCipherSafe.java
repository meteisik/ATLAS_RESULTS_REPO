import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SaffronCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronCipherAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("SAFFRON_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SaffronCipherSafeChecker()).isAuthorized(data);
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        try {
            PreparedStatement saffronCipherDelete = saffronCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCipherDelete.setString(1, data);
            if (authorized) {
                saffronCipherDelete.executeUpdate();
            }
        } finally {
            saffronCipherConnection.close();
        }
    }
}

class CWE284_P07_V2_SaffronCipherSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
