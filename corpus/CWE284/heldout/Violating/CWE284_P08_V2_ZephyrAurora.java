import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrAurora {

    public void deleteZephyrAuroraAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ZEPHYR_AURORA_ACCOUNT_ID");
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrAuroraSink()).applyZephyrAuroraDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrAuroraSink {
    public void applyZephyrAuroraDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        try {
            PreparedStatement zephyrAuroraDelete = zephyrAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrAuroraDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrAuroraDelete.executeUpdate();
            }
        } finally {
            zephyrAuroraConnection.close();
        }
    }
}
