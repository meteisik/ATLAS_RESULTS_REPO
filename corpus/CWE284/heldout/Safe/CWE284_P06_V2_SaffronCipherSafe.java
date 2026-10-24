import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSaffronCipherAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("SAFFRON_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronCipherSafeSink()).applySaffronCipherDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronCipherSafeSink {
    public void applySaffronCipherDeletion(String data, boolean authorized) throws SQLException {
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        try {
            PreparedStatement saffronCipherDelete = saffronCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCipherDelete.setString(1, data);
            if (authorized) {
                saffronCipherDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronCipherConnection.close();
        }
    }
}
