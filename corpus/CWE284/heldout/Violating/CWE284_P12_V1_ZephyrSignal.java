import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrSignal {

    public void deleteZephyrSignalAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrSignalBase baseObject = new CWE284_P12_V1_ZephyrSignalRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrSignalBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrSignalRemover extends CWE284_P12_V1_ZephyrSignalBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSignal");
        try {
            PreparedStatement zephyrSignalDelete = zephyrSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrSignalDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrSignalDelete.executeUpdate();
            }
        } finally {
            zephyrSignalConnection.close();
        }
    }
}
