import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrSignalSafe {

    public void deleteZephyrSignalAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrSignalSafeBase baseObject = new CWE284_P12_V1_ZephyrSignalSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrSignalSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrSignalSafeRemover extends CWE284_P12_V1_ZephyrSignalSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSignal");
        try {
            PreparedStatement zephyrSignalDelete = zephyrSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrSignalDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrSignalDelete.executeUpdate();
            }
        } finally {
            zephyrSignalConnection.close();
        }
    }
}
