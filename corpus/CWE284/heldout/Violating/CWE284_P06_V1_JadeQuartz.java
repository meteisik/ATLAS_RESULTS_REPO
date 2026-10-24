import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeQuartz {

    public void deleteJadeQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_QUARTZ_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeQuartzSink()).applyJadeQuartzDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeQuartzSink {
    public void applyJadeQuartzDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeQuartz");
        try {
            PreparedStatement jadeQuartzDelete = jadeQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeQuartzDelete.setString(1, data);
            jadeQuartzDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeQuartzConnection.close();
        }
    }
}
