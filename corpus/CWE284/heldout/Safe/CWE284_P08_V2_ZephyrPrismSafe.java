import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrPrismSafe {
    private static int privateFive = 5;

    public void deleteZephyrPrismAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrPrismSafeSink()).applyZephyrPrismDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrPrismSafeSink {
    public void applyZephyrPrismDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        try {
            PreparedStatement zephyrPrismDelete = zephyrPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrPrismDelete.executeUpdate();
            }
        } finally {
            zephyrPrismConnection.close();
        }
    }
}
