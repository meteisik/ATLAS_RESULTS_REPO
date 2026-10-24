import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrCascadeSafe {

    public void deleteZephyrCascadeAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ZEPHYR_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrCascadeSafeSink()).applyZephyrCascadeDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrCascadeSafeSink {
    public void applyZephyrCascadeDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        try {
            PreparedStatement zephyrCascadeDelete = zephyrCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCascadeDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrCascadeDelete.executeUpdate();
            }
        } finally {
            zephyrCascadeConnection.close();
        }
    }
}
