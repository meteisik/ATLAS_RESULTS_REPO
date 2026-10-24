import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeQuartzSafe {

    public void deleteJadeQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_QUARTZ_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeQuartzSafeSink()).applyJadeQuartzDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeQuartzSafeSink {
    public void applyJadeQuartzDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeQuartz");
        try {
            PreparedStatement jadeQuartzDelete = jadeQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeQuartzDelete.setString(1, data);
            if (authorized) {
                jadeQuartzDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeQuartzConnection.close();
        }
    }
}
