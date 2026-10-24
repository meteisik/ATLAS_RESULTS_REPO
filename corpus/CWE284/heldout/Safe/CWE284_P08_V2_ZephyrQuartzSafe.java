import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrQuartzSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteZephyrQuartzAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrQuartzSafeSink()).applyZephyrQuartzDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrQuartzSafeSink {
    public void applyZephyrQuartzDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        try {
            PreparedStatement zephyrQuartzDelete = zephyrQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrQuartzDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrQuartzDelete.executeUpdate();
            }
        } finally {
            zephyrQuartzConnection.close();
        }
    }
}
