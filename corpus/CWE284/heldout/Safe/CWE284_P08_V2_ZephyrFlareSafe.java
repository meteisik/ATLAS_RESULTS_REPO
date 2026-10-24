import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrFlareSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteZephyrFlareAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrFlareSafeSink()).applyZephyrFlareDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrFlareSafeSink {
    public void applyZephyrFlareDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        try {
            PreparedStatement zephyrFlareDelete = zephyrFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrFlareDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrFlareDelete.executeUpdate();
            }
        } finally {
            zephyrFlareConnection.close();
        }
    }
}
