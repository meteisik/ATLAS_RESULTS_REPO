import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeQuartzSafe {

    private String jadeQuartzAccountId;

    private boolean jadeQuartzAuthorized;

    private void applyJadeQuartzDeletion() throws SQLException {
        String data = jadeQuartzAccountId;
        boolean authorized = jadeQuartzAuthorized;
        Connection jadeQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeQuartz");
        try {
            PreparedStatement jadeQuartzDelete = jadeQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeQuartzDelete.setString(1, data);
            if (authorized) {
                jadeQuartzDelete.executeUpdate();
            }
        } finally {
            jadeQuartzConnection.close();
        }
    }

    public void deleteJadeQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_QUARTZ_ACCOUNT_ID");
        jadeQuartzAccountId = data;
        jadeQuartzAuthorized = isAuthorized(data);
        applyJadeQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
