import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeQuartzSafe {
    private static boolean privateTrue = true;

    public void deleteJadeQuartzAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("JADE_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
