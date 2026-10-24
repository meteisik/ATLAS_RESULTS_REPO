import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrCipherAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrCipherSink()).applyZephyrCipherDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrCipherSink {
    public void applyZephyrCipherDeletion(CWE284_P09_V2_ZephyrCipher.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCipher");
        try {
            PreparedStatement zephyrCipherDelete = zephyrCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCipherDelete.setString(1, data);
            zephyrCipherDelete.executeUpdate();
        } finally {
            zephyrCipherConnection.close();
        }
    }
}
