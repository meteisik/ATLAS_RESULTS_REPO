import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ZephyrAuroraSafe {

    public void deleteZephyrAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_AURORA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ZephyrAuroraSafeBase baseObject = new CWE284_P12_V1_ZephyrAuroraSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ZephyrAuroraSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ZephyrAuroraSafeRemover extends CWE284_P12_V1_ZephyrAuroraSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        try {
            PreparedStatement zephyrAuroraDelete = zephyrAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrAuroraDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrAuroraDelete.executeUpdate();
            }
        } finally {
            zephyrAuroraConnection.close();
        }
    }
}
