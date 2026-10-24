import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrCipherSafe {

    public void deleteZephyrCipherAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrCipherSafeSink()).applyZephyrCipherDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrCipherSafeSink {
    public void applyZephyrCipherDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCipher");
        try {
            PreparedStatement zephyrCipherDelete = zephyrCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCipherDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrCipherDelete.executeUpdate();
            }
        } finally {
            zephyrCipherConnection.close();
        }
    }
}
