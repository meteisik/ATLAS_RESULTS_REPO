import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ZephyrCipherSafe {
    private static int privateFive = 5;

    public static String data;

    public static boolean authorized;

    public void deleteZephyrCipherAccount() throws SQLException {
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ZephyrCipherSafeSink()).applyZephyrCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ZephyrCipherSafeSink {
    public void applyZephyrCipherDeletion() throws SQLException {
        String data = CWE284_P10_V2_ZephyrCipherSafe.data;
        boolean authorized = CWE284_P10_V2_ZephyrCipherSafe.authorized;
        Connection zephyrCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCipher");
        try {
            PreparedStatement zephyrCipherDelete = zephyrCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCipherDelete.setString(1, data);
            if (authorized) {
                zephyrCipherDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            zephyrCipherConnection.close();
        }
    }
}
