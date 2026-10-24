import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrCipherSafe {

    public void deleteZephyrCipherAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_CIPHER_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrCipherSafeBase baseObject = new CWE284_P12_V1_ZephyrCipherSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrCipherSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrCipherSafeRemover extends CWE284_P12_V1_ZephyrCipherSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
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
