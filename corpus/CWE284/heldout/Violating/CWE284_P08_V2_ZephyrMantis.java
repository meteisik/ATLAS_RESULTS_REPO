import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrMantis {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteZephyrMantisAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrMantisSink()).applyZephyrMantisDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrMantisSink {
    public void applyZephyrMantisDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        try {
            PreparedStatement zephyrMantisDelete = zephyrMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrMantisDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrMantisDelete.executeUpdate();
            }
        } finally {
            zephyrMantisConnection.close();
        }
    }
}
