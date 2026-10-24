import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeQuartz {

    private boolean checkJadeQuartzAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_QUARTZ_ACCOUNT_ID");
        boolean authorized = checkJadeQuartzAccess(data);
        Connection jadeQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeQuartz");
        try {
            PreparedStatement jadeQuartzDelete = jadeQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeQuartzDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
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
